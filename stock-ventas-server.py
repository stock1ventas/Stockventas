"""
╔══════════════════════════════════════════════════════╗
║         Stock Ventas — Servidor Backend v3           ║
║                                                      ║
║  Requiere: pip install flask flask-cors bcrypt       ║
║                                                      ║
║  Variables de entorno OBLIGATORIAS:                  ║
║    ADMIN_KEY → clave para el panel de administrador  ║
║    PORT      → puerto (default 5000)                 ║
║                                                      ║
║  Correr: python server_v2.py                         ║
╚══════════════════════════════════════════════════════╝
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from functools import wraps
from collections import defaultdict
import sqlite3, json, secrets, datetime, os, bcrypt

# ══════════════════════════════════════════════════════
#  CONFIGURACIÓN
# ══════════════════════════════════════════════════════
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}, r"/auth/*": {"origins": "*"}})

DB        = "stock_ventas.db"
ADMIN_KEY = os.environ.get("ADMIN_KEY")
PORT      = int(os.environ.get("PORT", 5000))

if not ADMIN_KEY:
    raise RuntimeError(
        "\n⚠  ADMIN_KEY no definida.\n"
        "   Corré: export ADMIN_KEY='tu-clave-secreta-larga'\n"
        "   En Railway: agregala en Variables de entorno.\n"
    )

# Rate limiting en memoria (por email)
_login_attempts = defaultdict(lambda: {"count": 0, "until": 0.0})


# ══════════════════════════════════════════════════════
#  BASE DE DATOS
# ══════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # mejor concurrencia
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    db = get_db()
    db.executescript("""
        -- Usuarios / negocios
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT    UNIQUE NOT NULL,
            pass_hash  TEXT    NOT NULL,
            biz_name   TEXT    NOT NULL,
            biz_type   TEXT    DEFAULT 'retail',
            lang       TEXT    DEFAULT 'es',
            plan       TEXT    DEFAULT 'basic',
            active     INTEGER DEFAULT 1,
            created    TEXT    DEFAULT (datetime('now','localtime'))
        );

        -- Sesiones con expiración
        CREATE TABLE IF NOT EXISTS sessions (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id  INTEGER NOT NULL,
            token    TEXT    UNIQUE NOT NULL,
            expires  TEXT    NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Datos por usuario (RLS: user_id aísla todo)
        CREATE TABLE IF NOT EXISTS user_data (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER UNIQUE NOT NULL,
            products     TEXT    DEFAULT '[]',
            sales        TEXT    DEFAULT '[]',
            config       TEXT    DEFAULT '{}',
            pricing_adj  TEXT    DEFAULT '[]',
            employees    TEXT    DEFAULT '[]',
            updated      TEXT    DEFAULT (datetime('now','localtime')),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Log de accesos (auditoría)
        CREATE TABLE IF NOT EXISTS access_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER,
            action    TEXT,
            ip        TEXT,
            ts        TEXT DEFAULT (datetime('now','localtime'))
        );
    """)
    db.commit()

    # Usuario demo (solo si no existe)
    try:
        demo_hash = bcrypt.hashpw(b"demo123", bcrypt.gensalt()).decode()
        db.execute(
            "INSERT OR IGNORE INTO users (email, pass_hash, biz_name, biz_type, lang) "
            "VALUES (?, ?, ?, ?, ?)",
            ("demo@demo.com", demo_hash, "Demo Negocio", "retail", "es")
        )
        db.commit()
    except Exception:
        pass
    finally:
        db.close()

    print("✓ Base de datos inicializada")


# ══════════════════════════════════════════════════════
#  SEGURIDAD
# ══════════════════════════════════════════════════════

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash.encode())


def sanitize(value, max_len=300) -> str:
    """Elimina caracteres peligrosos y limita largo."""
    if not isinstance(value, str):
        return ""
    return value.replace("<", "").replace(">", "").replace('"', "")[:max_len].strip()


def get_user_from_token(token: str):
    """RLS: valida el token y retorna el usuario activo. None si inválido o expirado."""
    if not token:
        return None
    db  = get_db()
    row = db.execute("""
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
          AND s.expires > datetime('now','localtime')
          AND u.active = 1
    """, (token,)).fetchone()
    db.close()
    return row


def require_auth(f):
    """Decorador RLS: solo usuarios con token válido pueden acceder."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        user  = get_user_from_token(token)
        if not user:
            return jsonify({"error": "No autorizado — token inválido o expirado"}), 401
        return f(user, *args, **kwargs)
    return wrapper


def check_admin() -> bool:
    return request.headers.get("X-Admin-Key", "") == ADMIN_KEY


def log_access(user_id, action):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO access_log (user_id, action, ip) VALUES (?, ?, ?)",
            (user_id, action, request.remote_addr)
        )
        db.commit()
        db.close()
    except Exception:
        pass


# ══════════════════════════════════════════════════════
#  AUTH — REGISTRO
# ══════════════════════════════════════════════════════
@app.post("/auth/register")
def register():
    data     = request.json or {}
    email    = sanitize(data.get("email", "")).lower()
    password = data.get("password", "")
    biz_name = sanitize(data.get("biz_name", ""))
    biz_type = sanitize(data.get("biz_type", "retail"))
    lang     = sanitize(data.get("lang", "es"))

    # Validaciones
    if not email or not password or not biz_name:
        return jsonify({"error": "Faltan campos obligatorios"}), 400
    if len(password) < 6:
        return jsonify({"error": "La contraseña debe tener al menos 6 caracteres"}), 400
    if "@" not in email or "." not in email:
        return jsonify({"error": "Email inválido"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (email, pass_hash, biz_name, biz_type, lang) "
            "VALUES (?, ?, ?, ?, ?)",
            (email, hash_password(password), biz_name, biz_type, lang)
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ya existe una cuenta con ese email"}), 409
    finally:
        db.close()

    return jsonify({"ok": True, "message": "Cuenta creada correctamente"}), 201


# ══════════════════════════════════════════════════════
#  AUTH — LOGIN con rate limiting
# ══════════════════════════════════════════════════════
@app.post("/auth/login")
def login():
    data     = request.json or {}
    email    = sanitize(data.get("email", "")).lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Faltan campos"}), 400

    # Rate limiting: 5 intentos → bloqueo 5 minutos
    att = _login_attempts[email]
    now = datetime.datetime.now().timestamp()
    if att["until"] > now:
        mins = int((att["until"] - now) / 60) + 1
        return jsonify({"error": f"Demasiados intentos. Esperá {mins} minuto(s)."}), 429

    db   = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE email = ? AND active = 1", (email,)
    ).fetchone()

    if not user or not verify_password(password, user["pass_hash"]):
        att["count"] = att.get("count", 0) + 1
        if att["count"] >= 5:
            att["until"] = now + 300   # 5 minutos
            att["count"] = 0
        db.close()
        return jsonify({"error": "Email o contraseña incorrectos"}), 401

    # Login correcto — limpiar intentos
    _login_attempts[email] = {"count": 0, "until": 0.0}

    # Crear token (válido 30 días)
    token   = secrets.token_urlsafe(48)
    expires = (datetime.datetime.now() + datetime.timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "INSERT INTO sessions (user_id, token, expires) VALUES (?, ?, ?)",
        (user["id"], token, expires)
    )
    db.commit()

    log_access(user["id"], "login")
    db.close()

    return jsonify({
        "ok":       True,
        "token":    token,
        "email":    user["email"],
        "biz_name": user["biz_name"],
        "biz_type": user["biz_type"],
        "lang":     user["lang"],
        "plan":     user["plan"]
    })


# ══════════════════════════════════════════════════════
#  AUTH — LOGOUT
# ══════════════════════════════════════════════════════
@app.post("/auth/logout")
def logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if token:
        db = get_db()
        db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        db.commit()
        db.close()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════
#  DATOS DEL USUARIO (RLS completo)
# ══════════════════════════════════════════════════════
@app.get("/api/data")
@require_auth
def get_data(user):
    """Carga todos los datos del usuario autenticado."""
    db  = get_db()
    row = db.execute(
        "SELECT * FROM user_data WHERE user_id = ?", (user["id"],)
    ).fetchone()
    db.close()

    if not row:
        return jsonify({
            "products": [], "sales": [], "config": {},
            "pricing_adj": [], "employees": []
        })

    return jsonify({
        "products":    json.loads(row["products"]),
        "sales":       json.loads(row["sales"]),
        "config":      json.loads(row["config"]),
        "pricing_adj": json.loads(row["pricing_adj"]),
        "employees":   json.loads(row["employees"]),
        "updated":     row["updated"]
    })


@app.post("/api/sync")
@require_auth
def sync_data(user):
    """Guarda todos los datos del usuario autenticado."""
    data = request.json or {}
    now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db   = get_db()

    exists = db.execute(
        "SELECT id FROM user_data WHERE user_id = ?", (user["id"],)
    ).fetchone()

    payload = (
        json.dumps(data.get("products",    []), ensure_ascii=False),
        json.dumps(data.get("sales",       []), ensure_ascii=False),
        json.dumps(data.get("config",      {}), ensure_ascii=False),
        json.dumps(data.get("pricing_adj", []), ensure_ascii=False),
        json.dumps(data.get("employees",   []), ensure_ascii=False),
        now
    )

    if exists:
        db.execute("""
            UPDATE user_data
            SET products=?, sales=?, config=?, pricing_adj=?, employees=?, updated=?
            WHERE user_id=?
        """, (*payload, user["id"]))
    else:
        db.execute("""
            INSERT INTO user_data
              (user_id, products, sales, config, pricing_adj, employees, updated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user["id"], *payload))

    db.commit()
    log_access(user["id"], "sync")
    db.close()

    return jsonify({"ok": True, "updated": now})


@app.patch("/api/profile")
@require_auth
def update_profile(user):
    """Actualiza nombre del negocio, tipo o idioma."""
    data     = request.json or {}
    biz_name = sanitize(data.get("biz_name", user["biz_name"]))
    biz_type = sanitize(data.get("biz_type", user["biz_type"]))
    lang     = sanitize(data.get("lang",     user["lang"]))

    db = get_db()
    db.execute(
        "UPDATE users SET biz_name=?, biz_type=?, lang=? WHERE id=?",
        (biz_name, biz_type, lang, user["id"])
    )
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.post("/api/change-password")
@require_auth
def change_password(user):
    """Cambia la contraseña verificando la actual."""
    data         = request.json or {}
    current_pass = data.get("current_password", "")
    new_pass     = data.get("new_password", "")

    if not current_pass or not new_pass:
        return jsonify({"error": "Faltan campos"}), 400
    if len(new_pass) < 6:
        return jsonify({"error": "La nueva contraseña debe tener al menos 6 caracteres"}), 400

    db   = get_db()
    full = db.execute("SELECT pass_hash FROM users WHERE id=?", (user["id"],)).fetchone()

    if not verify_password(current_pass, full["pass_hash"]):
        db.close()
        return jsonify({"error": "Contraseña actual incorrecta"}), 401

    db.execute(
        "UPDATE users SET pass_hash=? WHERE id=?",
        (hash_password(new_pass), user["id"])
    )
    # Invalida todas las sesiones activas excepto la actual
    current_token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    db.execute(
        "DELETE FROM sessions WHERE user_id=? AND token != ?",
        (user["id"], current_token)
    )
    db.commit()
    db.close()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════
#  PANEL ADMIN (solo el creador del software)
# ══════════════════════════════════════════════════════
@app.get("/admin/users")
def admin_users():
    if not check_admin():
        return jsonify({"error": "No autorizado"}), 403
    db   = get_db()
    rows = db.execute("""
        SELECT u.id, u.email, u.biz_name, u.biz_type, u.lang,
               u.plan, u.active, u.created, d.updated,
               (SELECT COUNT(*) FROM sessions s
                WHERE s.user_id=u.id
                  AND s.expires > datetime('now','localtime')) AS active_sessions
        FROM users u
        LEFT JOIN user_data d ON d.user_id = u.id
        ORDER BY u.created DESC
    """).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.get("/admin/users/<int:uid>/data")
def admin_user_data(uid):
    """Ver los datos completos de un cliente."""
    if not check_admin():
        return jsonify({"error": "No autorizado"}), 403
    db  = get_db()
    row = db.execute(
        "SELECT * FROM user_data WHERE user_id=?", (uid,)
    ).fetchone()
    db.close()
    if not row:
        return jsonify({"products": [], "sales": [], "config": {}})
    return jsonify({
        "products":    json.loads(row["products"]),
        "sales":       json.loads(row["sales"]),
        "config":      json.loads(row["config"]),
        "pricing_adj": json.loads(row["pricing_adj"]),
        "employees":   json.loads(row["employees"]),
        "updated":     row["updated"]
    })


@app.patch("/admin/users/<int:uid>")
def admin_update_user(uid):
    """Activar/desactivar cliente o cambiar plan."""
    if not check_admin():
        return jsonify({"error": "No autorizado"}), 403
    data   = request.json or {}
    fields = []
    values = []
    if "active" in data:
        fields.append("active=?")
        values.append(int(data["active"]))
    if "plan" in data:
        fields.append("plan=?")
        values.append(sanitize(data["plan"]))
    if not fields:
        return jsonify({"error": "Nada que actualizar"}), 400
    values.append(uid)
    db = get_db()
    db.execute(f"UPDATE users SET {', '.join(fields)} WHERE id=?", values)
    if "active" in data and not data["active"]:
        db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.delete("/admin/users/<int:uid>")
def admin_delete_user(uid):
    """Eliminar un usuario y todos sus datos."""
    if not check_admin():
        return jsonify({"error": "No autorizado"}), 403
    db = get_db()
    db.execute("DELETE FROM user_data WHERE user_id=?", (uid,))
    db.execute("DELETE FROM sessions  WHERE user_id=?", (uid,))
    db.execute("DELETE FROM users     WHERE id=?",      (uid,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.get("/admin/stats")
def admin_stats():
    """Resumen global de todos los clientes."""
    if not check_admin():
        return jsonify({"error": "No autorizado"}), 403
    db   = get_db()
    rows = db.execute("SELECT sales FROM user_data").fetchall()
    total_users   = db.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]
    total_sales   = 0
    total_revenue = 0.0
    for r in rows:
        sls = json.loads(r["sales"] or "[]")
        total_sales   += len(sls)
        total_revenue += sum(s.get("total", 0) for s in sls)
    db.close()
    return jsonify({
        "total_users":   total_users,
        "total_sales":   total_sales,
        "total_revenue": round(total_revenue, 2)
    })


@app.get("/admin/log")
def admin_log():
    """Últimas 100 acciones registradas."""
    if not check_admin():
        return jsonify({"error": "No autorizado"}), 403
    db   = get_db()
    rows = db.execute("""
        SELECT l.ts, l.action, l.ip, u.email, u.biz_name
        FROM access_log l
        LEFT JOIN users u ON u.id = l.user_id
        ORDER BY l.ts DESC LIMIT 100
    """).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ══════════════════════════════════════════════════════
#  HEALTH CHECK (para Railway / monitoreo)
# ══════════════════════════════════════════════════════
@app.get("/health")
def health():
    return jsonify({"status": "ok", "ts": datetime.datetime.now().isoformat()})


# ══════════════════════════════════════════════════════
#  INICIO
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    print(f"✓ Stock Ventas — Servidor corriendo en http://localhost:{PORT}")
    print(f"✓ Admin key configurada: {'Sí' if ADMIN_KEY else 'NO — ERROR'}")
    app.run(host="0.0.0.0", port=PORT, debug=False)


# ══════════════════════════════════════════════════════
#  SUSCRIPCIONES Y PAGOS
#  Compatible con cualquier proveedor de pagos.
#  Cuando elijas uno (MP, Stripe, PayPal, etc.)
#  solo configurás MP_ACCESS_TOKEN o STRIPE_SECRET_KEY
#  como variable de entorno y activás el webhook.
# ══════════════════════════════════════════════════════

PLANS = {
    "monthly": {"name": "Plan Completo",  "price_usd": 25,  "days": 30},
    "annual":  {"name": "Plan Anual",     "price_usd": 250, "days": 365},
}


def init_subscriptions():
    """Crear tabla de suscripciones si no existe."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS subscriptions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER UNIQUE NOT NULL,
            plan         TEXT    DEFAULT 'basic',
            status       TEXT    DEFAULT 'trial',
            paid_until   TEXT,
            payment_id   TEXT,
            provider     TEXT,
            created      TEXT    DEFAULT (datetime('now','localtime')),
            updated      TEXT    DEFAULT (datetime('now','localtime')),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    db.commit()
    db.close()


# ── Ver suscripción propia ────────────────────────────
@app.get("/api/subscription")
@require_auth
def get_subscription(user):
    """El cliente consulta su plan y fecha de vencimiento."""
    db  = get_db()
    row = db.execute(
        "SELECT * FROM subscriptions WHERE user_id=?", (user["id"],)
    ).fetchone()
    db.close()

    today = datetime.date.today().isoformat()

    if not row:
        # Sin suscripción: período de prueba de 14 días desde el registro
        db2   = get_db()
        user2 = db2.execute("SELECT created FROM users WHERE id=?", (user["id"],)).fetchone()
        db2.close()
        trial_until = (
            datetime.datetime.strptime(user2["created"][:10], "%Y-%m-%d")
            + datetime.timedelta(days=14)
        ).strftime("%Y-%m-%d")
        status = "trial" if today <= trial_until else "expired"
        return jsonify({
            "plan":       "trial",
            "status":     status,
            "paid_until": trial_until,
            "provider":   None
        })

    status = "active"
    if row["paid_until"] and row["paid_until"] < today:
        status = "expired"

    return jsonify({
        "plan":       row["plan"],
        "status":     status,
        "paid_until": row["paid_until"],
        "provider":   row["provider"]
    })


# ── Webhook genérico (compatible con cualquier proveedor) ──
@app.post("/webhook/payment")
def webhook_payment():
    """
    Endpoint universal para confirmar pagos.

    Cuando integrés un proveedor, configurás su webhook
    para que llame a esta URL con este payload:

    {
      "email":      "cliente@negocio.com",
      "plan":       "basic",
      "payment_id": "ID-del-pago-en-el-proveedor",
      "provider":   "stripe" | "mercadopago" | "paypal" | etc,
      "secret":     "tu-webhook-secret"   ← para verificar que es legítimo
    }

    El campo "secret" debe coincidir con WEBHOOK_SECRET
    en tus variables de entorno.
    """
    WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
    data = request.json or {}

    # Verificar que la llamada viene de tu proveedor
    if WEBHOOK_SECRET and data.get("secret") != WEBHOOK_SECRET:
        return jsonify({"error": "No autorizado"}), 401

    email      = sanitize(data.get("email", "")).lower()
    plan_key   = sanitize(data.get("plan", "basic"))
    payment_id = sanitize(data.get("payment_id", ""))
    provider   = sanitize(data.get("provider", "manual"))

    if not email or plan_key not in PLANS:
        return jsonify({"error": "Datos inválidos"}), 400

    plan      = PLANS[plan_key]
    paid_until = (
        datetime.datetime.now() + datetime.timedelta(days=plan["days"])
    ).strftime("%Y-%m-%d")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    db   = get_db()
    user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()

    if not user:
        db.close()
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Activar o actualizar suscripción
    db.execute("""
        INSERT INTO subscriptions
          (user_id, plan, status, paid_until, payment_id, provider, updated)
        VALUES (?, ?, 'active', ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          plan       = excluded.plan,
          status     = 'active',
          paid_until = excluded.paid_until,
          payment_id = excluded.payment_id,
          provider   = excluded.provider,
          updated    = excluded.updated
    """, (user["id"], plan_key, paid_until, payment_id, provider, now))

    db.execute(
        "UPDATE users SET plan=?, active=1 WHERE id=?",
        (plan_key, user["id"])
    )
    db.commit()
    log_access(user["id"], f"payment:{plan_key}:{provider}")
    db.close()

    return jsonify({
        "ok":        True,
        "plan":      plan["name"],
        "paid_until": paid_until
    })


# ── Activación manual desde el panel admin ────────────
@app.post("/admin/activate")
def admin_activate():
    """
    Activar un plan manualmente.
    Útil cuando el cliente paga por transferencia
    o cualquier método fuera del sistema.
    """
    if not check_admin():
        return jsonify({"error": "No autorizado"}), 403

    data     = request.json or {}
    email    = sanitize(data.get("email", "")).lower()
    plan_key = sanitize(data.get("plan", "basic"))
    note     = sanitize(data.get("note", ""))   # ej: "Pagó por transferencia"

    if not email or plan_key not in PLANS:
        return jsonify({"error": "Datos inválidos"}), 400

    # Reutilizamos el webhook interno
    request._cached_json = (
        {
            "email":      email,
            "plan":       plan_key,
            "payment_id": f"manual-{int(datetime.datetime.now().timestamp())}",
            "provider":   f"manual:{note}",
            "secret":     os.environ.get("WEBHOOK_SECRET", "")
        },
        True
    )
    return webhook_payment()


# ── Consultar todos los planes disponibles ────────────
@app.get("/plans")
def get_plans():
    """El frontend consulta esto para mostrar la página de precios."""
    return jsonify(PLANS)


# ── Suscripciones en el panel admin ──────────────────
@app.get("/admin/subscriptions")
def admin_subscriptions():
    """Ver todas las suscripciones activas y expiradas."""
    if not check_admin():
        return jsonify({"error": "No autorizado"}), 403
    db   = get_db()
    rows = db.execute("""
        SELECT u.email, u.biz_name, s.plan, s.status,
               s.paid_until, s.provider, s.updated
        FROM subscriptions s
        JOIN users u ON u.id = s.user_id
        ORDER BY s.updated DESC
    """).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# Inicializar tabla al arrancar
init_subscriptions()
