import os
import psycopg2
import psycopg2.extras
from flask import Flask, render_template_string, request, redirect, url_for, session, g, jsonify
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key_appstitch')
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ===================================================================
# CREDENCIALES DE GOOGLE OAUTH
# ===================================================================
# -------------------------------------------------------------------
# CREDENCIALES DE GOOGLE OAUTH (SEGURAS)
# -------------------------------------------------------------------
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)
# -------------------------------------------------------------------
# Base de Datos (PostgreSQL / Supabase)
# -------------------------------------------------------------------
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db():
    if 'db' not in g:
        database_url = os.environ.get('DATABASE_URL')
        g.db = psycopg2.connect(database_url, cursor_factory=psycopg2.extras.RealDictCursor)
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    # Inicialización segura conectando mediante psycopg2
    if not DATABASE_URL:
        return
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_email TEXT PRIMARY KEY,
                username TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS media (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                filename TEXT NOT NULL,
                category TEXT NOT NULL,
                user_name TEXT DEFAULT 'Anónimo',
                user_email TEXT DEFAULT '',
                user_avatar TEXT DEFAULT '',
                views INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS banned_users (
                id SERIAL PRIMARY KEY,
                user_name TEXT UNIQUE NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS likes (
                id SERIAL PRIMARY KEY,
                media_id INTEGER NOT NULL,
                user_email TEXT NOT NULL,
                UNIQUE(media_id, user_email)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id SERIAL PRIMARY KEY,
                media_id INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                user_avatar TEXT DEFAULT '',
                comment_text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS favorites (
                id SERIAL PRIMARY KEY,
                media_id INTEGER NOT NULL,
                user_email TEXT NOT NULL,
                UNIQUE(media_id, user_email)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS follows (
                id SERIAL PRIMARY KEY,
                follower_email TEXT NOT NULL,
                followed_email TEXT NOT NULL,
                UNIQUE(follower_email, followed_email)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS withdrawals (
                id SERIAL PRIMARY KEY,
                user_email TEXT NOT NULL,
                user_name TEXT NOT NULL,
                coins INTEGER NOT NULL,
                amount_cop INTEGER NOT NULL,
                payment_info TEXT NOT NULL,
                status TEXT DEFAULT 'Pendiente',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print("Aviso al inicializar la base de datos:", e)

init_db()

def get_user_display_name(email, default_name):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT username FROM user_profiles WHERE user_email = %s', (email,))
    profile = cursor.fetchone()
    cursor.close()
    if profile and profile['username']:
        return profile['username']
    return default_name

def is_banned(user_name):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM banned_users WHERE user_name = %s', (user_name,))
    banned = cursor.fetchone()
    cursor.close()
    return banned is not None

# -------------------------------------------------------------------
# Rutas de Autenticación
# -------------------------------------------------------------------
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def authorize_google():
    token = google.authorize_access_token()
    user_info = token.get('userinfo')
    
    if user_info:
        email = user_info.get('email')
        default_name = user_info.get('name')
        
        display_name = get_user_display_name(email, default_name)
        
        session['user'] = {
            'name': display_name,
            'real_name': default_name,
            'email': email,
            'picture': user_info.get('picture')
        }
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

# -------------------------------------------------------------------
# Rutas Principales
# -------------------------------------------------------------------
@app.route('/')
def index():
    category = request.args.get('category', 'all')
    media_id_param = request.args.get('media_id')
    db = get_db()
    cursor = db.cursor()
    
    base_query = """
        SELECT media.* FROM media 
        LEFT JOIN (SELECT media_id, COUNT(*) as like_count FROM likes GROUP BY media_id) l ON media.id = l.media_id
    """
    
    # Adaptación de fechas y ordenamiento compatible con PostgreSQL
    query_order = """
        ORDER BY 
        CASE WHEN (media.created_at + INTERVAL '8 hours') >= CURRENT_TIMESTAMP THEN 0 ELSE 1 END ASC,
        CASE WHEN (media.created_at + INTERVAL '8 hours') >= CURRENT_TIMESTAMP THEN media.id END DESC,
        COALESCE(l.like_count, 0) DESC,
        media.id DESC
    """
    
    if category in ['image', 'video', 'short']:
        cursor.execute(f'{base_query} WHERE category = %s {query_order}', (category,))
        items_raw = cursor.fetchall()
    elif category == 'favorites':
        if 'user' not in session:
            cursor.close()
            return redirect(url_for('index'))
        cursor.execute('''
            SELECT m.* FROM media m 
            JOIN favorites f ON m.id = f.media_id 
            WHERE f.user_email = %s ORDER BY f.id DESC
        ''', (session['user']['email'],))
        items_raw = cursor.fetchall()
    else:
        cursor.execute(f'{base_query} {query_order}')
        items_raw = cursor.fetchall()
        
    items = []
    user_email = session.get('user', {}).get('email', '')
    
    for item in items_raw:
        item_dict = dict(item)
        item_id = item_dict['id']
        
        item_dict['user_name'] = get_user_display_name(item_dict['user_email'], item_dict['user_name'])
        
        cursor.execute('SELECT COUNT(*) as c FROM likes WHERE media_id = %s', (item_id,))
        likes_cnt = cursor.fetchone()['c']
        item_dict['likes_count'] = likes_cnt
        
        item_dict['user_liked'] = False
        item_dict['user_favorited'] = False
        if user_email:
            cursor.execute('SELECT 1 FROM likes WHERE media_id = %s AND user_email = %s', (item_id, user_email))
            liked = cursor.fetchone()
            cursor.execute('SELECT 1 FROM favorites WHERE media_id = %s AND user_email = %s', (item_id, user_email))
            fav = cursor.fetchone()
            item_dict['user_liked'] = liked is not None
            item_dict['user_favorited'] = fav is not None
            
        cursor.execute('SELECT * FROM comments WHERE media_id = %s ORDER BY id DESC', (item_id,))
        comments = cursor.fetchall()
        comments_list = [dict(c) for c in comments]
        item_dict['comments'] = comments_list
        
        items.append(item_dict)
    
    cursor.close()
    
    if category == 'short':
        return render_template_string(SHORTS_FEED_HTML, items=items, media_id_param=media_id_param)
        
    return render_template_string(LAYOUT_HTML, items=items, active_category=category, media_id_param=media_id_param)

# -------------------------------------------------------------------
# Perfil de Creador y Actualización de Apodo / Username
# -------------------------------------------------------------------
@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('index'))
    
    user_email = session['user']['email']
    db = get_db()
    cursor = db.cursor()
    
    real_name = session['user'].get('real_name', session['user'].get('name', 'Usuario'))
    display_name = get_user_display_name(user_email, real_name)
    session['user']['name'] = display_name
    
    if is_banned(display_name):
        cursor.close()
        return "<h1>Acceso Denegado</h1><p>Tu cuenta ha sido suspendida.</p>"
        
    cursor.execute('SELECT * FROM media WHERE user_email = %s ORDER BY id DESC', (user_email,))
    items = cursor.fetchall()
    
    cursor.execute('SELECT COUNT(*) as c FROM follows WHERE followed_email = %s', (user_email,))
    followers_count = cursor.fetchone()['c']
    
    cursor.execute('SELECT COUNT(*) as c FROM follows WHERE follower_email = %s', (user_email,))
    following_count = cursor.fetchone()['c']
    
    cursor.execute('SELECT SUM(views) as total FROM media WHERE user_email = %s', (user_email,))
    total_views_row = cursor.fetchone()
    total_views = total_views_row['total'] if total_views_row and total_views_row['total'] else 0
    
    total_coins = total_views if total_views >= 100 else 0
    estimated_cop = int((total_coins / 1000) * 3000)
        
    cursor.execute('SELECT * FROM withdrawals WHERE user_email = %s ORDER BY id DESC', (user_email,))
    withdrawals = cursor.fetchall()
    cursor.close()
    
    return render_template_string(PROFILE_HTML, 
                                  items=items, 
                                  followers_count=followers_count, 
                                  following_count=following_count, 
                                  total_views=total_views, 
                                  total_coins=total_coins,
                                  estimated_cop=estimated_cop,
                                  withdrawals=withdrawals,
                                  current_username=display_name)

@app.route('/api/update-username', methods=['POST'])
def update_username():
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
        
    new_username = request.form.get('username', '').strip()
    if not new_username:
        return jsonify({'error': 'empty'}), 400
        
    user_email = session['user']['email']
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        INSERT INTO user_profiles (user_email, username) VALUES (%s, %s)
        ON CONFLICT (user_email) DO UPDATE SET username = EXCLUDED.username
    ''', (user_email, new_username))
    cursor.execute('UPDATE media SET user_name = %s WHERE user_email = %s', (new_username, user_email))
    db.commit()
    cursor.close()
    
    session['user']['name'] = new_username
    return jsonify({'status': 'success', 'username': new_username})

@app.route('/api/follow/<email_to_follow>', methods=['POST'])
def toggle_follow(email_to_follow):
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    follower_email = session['user']['email']
    if follower_email == email_to_follow:
        return jsonify({'error': 'self_follow'}), 400
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM follows WHERE follower_email = %s AND followed_email = %s', (follower_email, email_to_follow))
    existing = cursor.fetchone()
    
    if existing:
        cursor.execute('DELETE FROM follows WHERE follower_email = %s AND followed_email = %s', (follower_email, email_to_follow))
        is_following = False
    else:
        cursor.execute('INSERT INTO follows (follower_email, followed_email) VALUES (%s, %s)', (follower_email, email_to_follow))
        is_following = True
    db.commit()
    
    cursor.execute('SELECT COUNT(*) as c FROM follows WHERE followed_email = %s', (email_to_follow,))
    new_count = cursor.fetchone()['c']
    cursor.close()
    
    return jsonify({'is_following': is_following, 'followers_count': new_count})

@app.route('/api/withdraw', methods=['POST'])
def request_withdrawal():
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
        
    user_email = session['user']['email']
    user_name = session['user']['name']
    payment_info = request.form.get('payment_info', '').strip()
    
    if not payment_info:
        return jsonify({'error': 'missing_info'}), 400
        
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('SELECT COUNT(*) as c FROM follows WHERE followed_email = %s', (user_email,))
    followers_count = cursor.fetchone()['c']
    if followers_count < 50:
        cursor.close()
        return jsonify({'error': 'not_enough_followers'}), 400
        
    cursor.execute('SELECT SUM(views) as total FROM media WHERE user_email = %s', (user_email,))
    total_views_row = cursor.fetchone()
    total_views = total_views_row['total'] if total_views_row and total_views_row['total'] else 0
    total_coins = total_views if total_views >= 100 else 0
    
    cursor.execute('SELECT SUM(coins) as total FROM withdrawals WHERE user_email = %s AND status != \'Rechazado\'', (user_email,))
    withdrawn_row = cursor.fetchone()
    withdrawn_coins = withdrawn_row['total'] if withdrawn_row and withdrawn_row['total'] else 0
    
    available_coins = total_coins - withdrawn_coins
    
    if available_coins < 1000:
        cursor.close()
        return jsonify({'error': 'not_enough_coins'}), 400
        
    amount_cop = int((available_coins / 1000) * 3000)
        
    cursor.execute('INSERT INTO withdrawals (user_email, user_name, coins, amount_cop, payment_info) VALUES (%s, %s, %s, %s, %s)',
               (user_email, user_name, available_coins, amount_cop, payment_info))
    db.commit()
    cursor.close()
    
    return jsonify({'status': 'success', 'coins_withdrawn': available_coins, 'amount_cop': amount_cop})

# -------------------------------------------------------------------
# APIs de Interacciones
# -------------------------------------------------------------------
@app.route('/api/view/<int:media_id>', methods=['POST'])
def register_view(media_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE media SET views = views + 1 WHERE id = %s', (media_id,))
    db.commit()
    cursor.execute('SELECT views FROM media WHERE id = %s', (media_id,))
    new_views = cursor.fetchone()['views']
    cursor.close()
    return jsonify({'status': 'ok', 'views': new_views})

@app.route('/api/like/<int:media_id>', methods=['POST'])
def toggle_like(media_id):
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
        
    user_email = session['user']['email']
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('SELECT * FROM likes WHERE media_id = %s AND user_email = %s', (media_id, user_email))
    existing = cursor.fetchone()
    if existing:
        cursor.execute('DELETE FROM likes WHERE media_id = %s AND user_email = %s', (media_id, user_email))
        liked = False
    else:
        cursor.execute('INSERT INTO likes (media_id, user_email) VALUES (%s, %s)', (media_id, user_email))
        liked = True
    db.commit()
    
    cursor.execute('SELECT COUNT(*) as c FROM likes WHERE media_id = %s', (media_id,))
    likes_count = cursor.fetchone()['c']
    cursor.close()
    
    return jsonify({'liked': liked, 'likes_count': likes_count})

@app.route('/api/favorite/<int:media_id>', methods=['POST'])
def toggle_favorite(media_id):
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
        
    user_email = session['user']['email']
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('SELECT * FROM favorites WHERE media_id = %s AND user_email = %s', (media_id, user_email))
    existing = cursor.fetchone()
    if existing:
        cursor.execute('DELETE FROM favorites WHERE media_id = %s AND user_email = %s', (media_id, user_email))
        favorited = False
    else:
        cursor.execute('INSERT INTO favorites (media_id, user_email) VALUES (%s, %s)', (media_id, user_email))
        favorited = True
    db.commit()
    cursor.close()
    
    return jsonify({'favorited': favorited})

@app.route('/api/comment/<int:media_id>', methods=['POST'])
def add_comment(media_id):
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
        
    comment_text = request.form.get('comment_text', '').strip()
    if not comment_text:
        return jsonify({'error': 'empty'}), 400
        
    user_name = session['user']['name']
    user_avatar = session['user'].get('picture', '')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO comments (media_id, user_name, user_avatar, comment_text) VALUES (%s, %s, %s, %s)',
               (media_id, user_name, user_avatar, comment_text))
    db.commit()
    cursor.close()
    
    return jsonify({
        'user_name': user_name,
        'user_avatar': user_avatar,
        'comment_text': comment_text
    })

# -------------------------------------------------------------------
# Gestión de Contenido y Panel Secreto de Administrador
# -------------------------------------------------------------------
@app.route('/delete/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    if 'user' not in session:
        return redirect(url_for('index'))
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM media WHERE id = %s', (item_id,))
    item = cursor.fetchone()
    
    if item and item['user_email'] == session['user']['email']:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], item['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        cursor.execute('DELETE FROM media WHERE id = %s', (item_id,))
        cursor.execute('DELETE FROM likes WHERE media_id = %s', (item_id,))
        cursor.execute('DELETE FROM comments WHERE media_id = %s', (item_id,))
        cursor.execute('DELETE FROM favorites WHERE media_id = %s', (item_id,))
        db.commit()
    cursor.close()
        
    return redirect(url_for('profile'))

@app.route('/admin/secreto-maestro-99')
def admin_master():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM media ORDER BY id DESC')
    items = cursor.fetchall()
    cursor.execute('SELECT * FROM banned_users')
    banned = cursor.fetchall()
    banned_names = [b['user_name'] for b in banned]
    cursor.execute('SELECT * FROM withdrawals ORDER BY id DESC')
    withdrawals = cursor.fetchall()
    cursor.close()
    
    return render_template_string(ADMIN_MASTER_HTML, items=items, banned_names=banned_names, withdrawals=withdrawals)

@app.route('/admin/pay-withdrawal/<int:w_id>', methods=['POST'])
def admin_pay_withdrawal(w_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE withdrawals SET status = \'Pagado\' WHERE id = %s', (w_id,))
    db.commit()
    cursor.close()
    return redirect(url_for('admin_master'))

@app.route('/admin/delete-media/<int:item_id>', methods=['POST'])
def admin_delete_media(item_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM media WHERE id = %s', (item_id,))
    item = cursor.fetchone()
    if item:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], item['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        cursor.execute('DELETE FROM media WHERE id = %s', (item_id,))
        cursor.execute('DELETE FROM likes WHERE media_id = %s', (item_id,))
        cursor.execute('DELETE FROM comments WHERE media_id = %s', (item_id,))
        cursor.execute('DELETE FROM favorites WHERE media_id = %s', (item_id,))
        db.commit()
    cursor.close()
    return redirect(url_for('admin_master'))

@app.route('/admin/ban-user', methods=['POST'])
def admin_ban_user():
    user_name = request.form.get('user_name')
    if user_name:
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute('INSERT INTO banned_users (user_name) VALUES (%s)', (user_name,))
            db.commit()
        except Exception:
            pass
        cursor.close()
    return redirect(url_for('admin_master'))

@app.route('/admin/unban-user', methods=['POST'])
def admin_unban_user():
    user_name = request.form.get('user_name')
    if user_name:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('DELETE FROM banned_users WHERE user_name = %s', (user_name,))
        db.commit()
        cursor.close()
    return redirect(url_for('admin_master'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('index'))
        
    user_name = session['user']['name']
    if is_banned(user_name):
        return "No puedes subir contenido porque estás baneado.", 403
        
    title = request.form.get('title')
    description = request.form.get('description', '')
    category = request.form.get('category')
    file = request.files.get('file')
    
    if file and file.filename != '':
        filename = file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        user_email = session['user']['email']
        user_avatar = session['user'].get('picture', '')
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'INSERT INTO media (title, description, filename, category, user_name, user_email, user_avatar, views) VALUES (%s, %s, %s, %s, %s, %s, %s, 0)',
            (title, description, filename, category, user_name, user_email, user_avatar)
        )
        db.commit()
        cursor.close()
        
    return redirect(url_for('index', category=category))

# -------------------------------------------------------------------
# VISTAS HTML (Intactas)
# -------------------------------------------------------------------
LAYOUT_HTML = '''
<!DOCTYPE html>
<html lang="es" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Plataforma de Contenido y Creadores</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: { colors: { brand: '#ff3366', darkbg: '#0f0f12', cardbg: '#18181c', hoverbg: '#242429' } } }
        }
    </script>
    <script src="https://unpkg.com/lucide@latest"></script>
</head>
<body class="bg-darkbg text-gray-100 font-sans min-h-screen flex flex-col">
    <header class="h-16 border-b border-gray-800 bg-cardbg/85 backdrop-blur-md sticky top-0 z-40 px-4 md:px-6 flex items-center justify-between">
        <div class="flex items-center gap-4">
            <a href="/" class="flex items-center gap-2 text-xl font-black text-brand tracking-wider">
                <i data-lucide="play-circle" class="w-8 h-8 fill-brand text-darkbg"></i>
                <span>MEDIA<span class="text-white">PRO</span></span>
            </a>
        </div>
        <div class="flex items-center gap-3">
            {% if session.user %}
                <button onclick="openUploadModal()" class="flex items-center gap-2 bg-brand hover:bg-rose-600 text-white font-semibold px-3 py-1.5 md:px-4 md:py-2 rounded-full text-xs md:text-sm transition shadow-lg shadow-brand/20">
                    <i data-lucide="upload-cloud" class="w-4 h-4"></i> Subir
                </button>
                <a href="/profile" class="flex items-center gap-2 bg-hoverbg py-1 px-3 rounded-full border border-gray-700 hover:border-brand transition">
                    <img src="{{ session.user.picture }}" class="w-6 h-6 md:w-7 md:h-7 rounded-full object-cover">
                    <span class="text-xs md:text-sm font-medium">@{{ session.user.name }}</span>
                </a>
                <a href="/logout" class="text-gray-400 hover:text-red-400 p-1"><i data-lucide="log-out" class="w-5 h-5"></i></a>
            {% else %}
                <a href="/login/google" class="flex items-center gap-2 bg-white text-gray-900 font-medium px-3 py-1.5 md:px-4 md:py-2 rounded-full hover:bg-gray-200 transition text-xs md:text-sm">
                    <span>Iniciar sesión</span>
                </a>
            {% endif %}
        </div>
    </header>

    <div class="md:hidden bg-cardbg border-b border-gray-800 p-2 flex items-center justify-around overflow-x-auto no-scrollbar">
        <a href="/?category=all" class="px-3 py-1.5 rounded-lg text-xs font-semibold shrink-0 {% if active_category == 'all' %}bg-brand text-white{% else %}text-gray-400{% endif %}">Todo</a>
        <a href="/?category=image" class="px-3 py-1.5 rounded-lg text-xs font-semibold shrink-0 {% if active_category == 'image' %}bg-brand text-white{% else %}text-gray-400{% endif %}">Imágenes</a>
        <a href="/?category=video" class="px-3 py-1.5 rounded-lg text-xs font-semibold shrink-0 {% if active_category == 'video' %}bg-brand text-white{% else %}text-gray-400{% endif %}">Videos</a>
        <a href="/?category=short" class="px-3 py-1.5 rounded-lg text-xs font-semibold shrink-0 {% if active_category == 'short' %}bg-brand text-white{% else %}text-gray-400{% endif %}">Shorts</a>
        {% if session.user %}
        <a href="/profile" class="px-3 py-1.5 rounded-lg text-xs font-semibold shrink-0 text-gray-400">Mi Perfil</a>
        {% endif %}
    </div>

    <div class="flex flex-1 relative">
        <aside class="w-64 border-r border-gray-800 bg-cardbg p-4 flex flex-col gap-2 shrink-0 h-[calc(100vh-4rem)] sticky top-16 hidden md:flex overflow-y-auto">
            <span class="text-xs font-bold text-gray-500 uppercase px-3 mb-1 tracking-wider">Explorar</span>
            <a href="/?category=all" class="flex items-center gap-3 px-3 py-2.5 rounded-xl font-medium transition {% if active_category == 'all' %}bg-brand text-white{% else %}text-gray-400 hover:bg-hoverbg hover:text-white{% endif %}"><i data-lucide="grid" class="w-5 h-5"></i> Todo</a>
            <a href="/?category=image" class="flex items-center gap-3 px-3 py-2.5 rounded-xl font-medium transition {% if active_category == 'image' %}bg-brand text-white{% else %}text-gray-400 hover:bg-hoverbg hover:text-white{% endif %}"><i data-lucide="image" class="w-5 h-5"></i> Imágenes</a>
            <a href="/?category=video" class="flex items-center gap-3 px-3 py-2.5 rounded-xl font-medium transition {% if active_category == 'video' %}bg-brand text-white{% else %}text-gray-400 hover:bg-hoverbg hover:text-white{% endif %}"><i data-lucide="film" class="w-5 h-5"></i> Videos Largos</a>
            <a href="/?category=short" class="flex items-center gap-3 px-3 py-2.5 rounded-xl font-medium transition {% if active_category == 'short' %}bg-brand text-white{% else %}text-gray-400 hover:bg-hoverbg hover:text-white{% endif %}"><i data-lucide="smartphone" class="w-5 h-5"></i> Shorts</a>
            {% if session.user %}
                <span class="text-xs font-bold text-gray-500 uppercase px-3 mt-4 mb-1 tracking-wider">Mi Espacio</span>
                <a href="/profile" class="flex items-center gap-3 px-3 py-2.5 rounded-xl font-medium transition text-gray-400 hover:bg-hoverbg hover:text-white"><i data-lucide="user-check" class="w-5 h-5"></i> Mi Perfil & Creador</a>
                <a href="/?category=favorites" class="flex items-center gap-3 px-3 py-2.5 rounded-xl font-medium transition {% if active_category == 'favorites' %}bg-brand text-white{% else %}text-gray-400 hover:bg-hoverbg hover:text-white{% endif %}"><i data-lucide="bookmark" class="w-5 h-5"></i> Favoritos</a>
            {% endif %}
        </aside>

        <main class="flex-1 p-4 md:p-6">
            {% if active_category != 'short' %}
            <div class="bg-gradient-to-br from-rose-900/40 to-cardbg rounded-2xl overflow-hidden border border-rose-500/30 flex flex-col mb-6 p-4 md:p-6 shadow-xl relative">
                <span class="absolute top-4 right-4 bg-rose-500 text-white text-[10px] uppercase font-bold px-2.5 py-1 rounded-full tracking-wider shadow">Patrocinado</span>
                <div class="flex flex-col md:flex-row items-center gap-4 md:gap-6">
                    <div class="w-full md:w-1/3 h-32 md:h-36 bg-black/40 rounded-xl overflow-hidden flex items-center justify-center border border-rose-500/20">
                        <div class="text-center p-4">
                            <i data-lucide="zap" class="w-8 h-8 md:w-10 md:h-10 text-rose-400 mx-auto mb-1 animate-bounce"></i>
                            <span class="text-xs font-bold text-rose-300 uppercase tracking-widest">Publicidad</span>
                        </div>
                    </div>
                    <div class="flex-1 flex flex-col justify-center text-center md:text-left">
                        <h3 class="text-lg md:text-xl font-bold text-white mb-1">¡Promociona tu marca aquí!</h3>
                        <p class="text-xs md:text-sm text-gray-300 mb-3">Llega a miles de usuarios diariamente con nuestra red de contenido.</p>
                        <a href="#" onclick="alert('Espacio disponible.'); return false;" class="bg-brand hover:bg-rose-600 text-white font-bold py-2 px-5 rounded-xl text-xs transition self-center md:self-start shadow-lg shadow-brand/20">Saber más</a>
                    </div>
                </div>
            </div>
            {% endif %}

            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 md:gap-6">
                {% for item in items %}
                    <div class="bg-cardbg rounded-2xl overflow-hidden border border-gray-800 flex flex-col cursor-pointer hover:border-gray-600 transition" id="card-{{ item.id }}" onclick="openModal({{ item.id }}, '{{ item.category }}', '{{ url_for('static', filename='uploads/' + item.filename) }}', '{{ item.title }}', '{{ item.description }}', '{{ item.user_name }}', '{{ item.user_email }}', {{ item.likes_count }}, {{ item.views }}, {{ 'true' if item.user_liked else 'false' }}, {{ 'true' if item.user_favorited else 'false' }}, {{ item.comments|tojson }})">
                        <div class="aspect-video bg-black relative">
                            {% if item.category == 'image' %}
                                <img src="{{ url_for('static', filename='uploads/' + item.filename) }}" class="w-full h-full object-cover">
                            {% else %}
                                <video class="w-full h-full object-cover pointer-events-none"><source src="{{ url_for('static', filename='uploads/' + item.filename) }}" type="video/mp4"></video>
                            {% endif %}
                            <div class="absolute bottom-2 right-2 bg-black/60 backdrop-blur-md text-white text-[10px] font-bold px-2 py-1 rounded-md flex items-center gap-1">
                                <i data-lucide="eye" class="w-3 h-3"></i> {{ item.views }}
                            </div>
                        </div>
                        <div class="p-4 flex gap-3 items-start justify-between">
                            <div class="flex items-start gap-3 overflow-hidden">
                                <div class="w-9 h-9 rounded-full bg-gray-700 shrink-0 flex items-center justify-center font-bold text-xs">{{ item.user_name[0] }}</div>
                                <div class="overflow-hidden">
                                    <h3 class="font-semibold text-sm truncate text-white">{{ item.title }}</h3>
                                    <p class="text-xs text-gray-400 mt-0.5">@{{ item.user_name }}</p>
                                </div>
                            </div>
                            <div class="flex items-center gap-2 shrink-0">
                                <button onclick="shareMedia(event, {{ item.id }})" class="p-1.5 hover:bg-hoverbg rounded-lg text-gray-400 hover:text-white transition" title="Compartir enlace">
                                    <i data-lucide="share-2" class="w-4 h-4"></i>
                                </button>
                                <span class="flex items-center gap-1 text-xs text-rose-400 font-bold">
                                    <i data-lucide="heart" class="w-3.5 h-3.5 fill-rose-400"></i> {{ item.likes_count }}
                                </span>
                            </div>
                        </div>
                    </div>
                {% endfor %}
            </div>
            {% if not items %}<div class="flex flex-col items-center justify-center h-64 text-gray-500 gap-3"><i data-lucide="folder-open" class="w-12 h-12 stroke-1"></i><p class="text-lg font-medium">No hay contenido disponible.</p></div>{% endif %}
        </main>
    </div>

    <!-- MODAL PRINCIPAL -->
    <div id="mediaModal" class="fixed inset-0 bg-black/90 z-50 flex items-center justify-center hidden p-4 backdrop-blur-md">
        <button onclick="closeModal()" class="absolute top-6 right-6 text-gray-400 hover:text-white bg-white/10 hover:bg-white/20 p-3 rounded-full transition z-50">
            <i data-lucide="x" class="w-6 h-6"></i>
        </button>
        <div class="max-w-6xl w-full max-h-[90vh] flex flex-col md:flex-row bg-cardbg border border-gray-800 rounded-3xl overflow-hidden shadow-2xl">
            <div class="flex-1 bg-black flex items-center justify-center min-h-[300px] md:min-h-[500px] relative group" id="modalMediaContainer"></div>
            <div class="w-full md:w-96 p-6 flex flex-col justify-between border-t md:border-t-0 md:border-l border-gray-800 bg-cardbg overflow-hidden">
                <div class="overflow-y-auto no-scrollbar pr-1">
                    <div class="flex items-center justify-between mb-3">
                        <span id="modalCategory" class="text-[10px] font-bold uppercase tracking-wider px-2.5 py-1 rounded-full bg-brand/20 text-brand"></span>
                        <div class="flex items-center gap-2 text-xs text-gray-400">
                            <i data-lucide="eye" class="w-4 h-4"></i> <span id="modalViews">0</span> vistas
                        </div>
                    </div>
                    
                    <h2 id="modalTitle" class="text-xl font-bold text-white mb-2"></h2>
                    <p id="modalDescription" class="text-sm text-gray-300 leading-relaxed whitespace-pre-line mb-4"></p>

                    <div class="flex items-center justify-between bg-darkbg p-3 rounded-2xl border border-gray-800 mb-4">
                        <div class="flex items-center gap-3">
                            <div class="w-10 h-10 rounded-full bg-brand text-white font-bold flex items-center justify-center" id="modalAvatar">U</div>
                            <div>
                                <h4 id="modalAuthor" class="text-sm font-bold text-white"></h4>
                                <span class="text-[10px] text-gray-400">Creador de contenido</span>
                            </div>
                        </div>
                        <button id="btnFollowModal" onclick="toggleFollowAuthor()" class="text-xs font-bold px-3 py-1.5 rounded-xl bg-hoverbg hover:bg-gray-700 border border-gray-700 transition">Seguir</button>
                    </div>

                    <div class="flex items-center gap-3 mb-6">
                        <button id="btnLike" onclick="toggleLikeCurrent()" class="flex-1 flex items-center justify-center gap-2 bg-hoverbg hover:bg-gray-800 border border-gray-700 py-2 rounded-xl transition text-sm font-semibold">
                            <i id="iconLike" data-lucide="heart" class="w-4 h-4"></i> <span id="txtLikesCount">0</span>
                        </button>
                        <button id="btnFav" onclick="toggleFavCurrent()" class="flex items-center justify-center p-2.5 bg-hoverbg hover:bg-gray-800 border border-gray-700 rounded-xl transition">
                            <i id="iconFav" data-lucide="bookmark" class="w-4 h-4"></i>
                        </button>
                        <button onclick="shareMedia(event, currentMediaId)" class="flex items-center justify-center p-2.5 bg-hoverbg hover:bg-gray-800 border border-gray-700 rounded-xl transition text-gray-300 hover:text-white" title="Compartir enlace">
                            <i data-lucide="share-2" class="w-4 h-4"></i>
                        </button>
                    </div>

                    <h3 class="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">Comentarios</h3>
                    <div id="commentsContainer" class="flex flex-col gap-3 mb-4 max-h-40 overflow-y-auto pr-1"></div>
                </div>

                <div class="pt-4 border-t border-gray-800">
                    {% if session.user %}
                    <form onsubmit="postComment(event)" class="flex gap-2">
                        <input type="text" id="inputComment" placeholder="Escribe un comentario..." required class="flex-1 bg-darkbg border border-gray-700 rounded-xl px-3 py-2 text-xs focus:outline-none focus:border-brand">
                        <button type="submit" class="bg-brand text-white font-bold px-3 py-2 rounded-xl text-xs hover:bg-rose-600 transition"><i data-lucide="send" class="w-3.5 h-3.5"></i></button>
                    </form>
                    {% else %}
                    <p class="text-xs text-gray-500 text-center"><a href="/login/google" class="text-brand underline">Inicia sesión</a> para comentar.</p>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>

    <!-- PANTALLA COMPLETA REAL -->
    <div id="trueFullscreenOverlay" class="fixed inset-0 bg-black z-[100] hidden flex items-center justify-center">
        <button onclick="closeTrueFullscreen()" class="absolute top-6 right-6 text-white bg-white/20 hover:bg-white/40 p-3 rounded-full transition z-[110]">
            <i data-lucide="x" class="w-8 h-8"></i>
        </button>
        <div class="w-full h-full flex items-center justify-center p-4" id="trueFullscreenContainer"></div>
    </div>

    <!-- MODAL SUBIR -->
    <div id="uploadModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
        <div class="bg-cardbg border border-gray-800 w-full max-w-md rounded-2xl p-6 shadow-2xl relative">
            <button onclick="closeUploadModal()" class="absolute top-4 right-4 text-gray-400 hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button>
            <h2 class="text-xl font-bold mb-4 flex items-center gap-2"><i data-lucide="upload" class="text-brand"></i> Subir contenido</h2>
            <form action="/upload" method="POST" enctype="multipart/form-data" class="flex flex-col gap-4">
                <div><label class="text-xs text-gray-400 font-semibold mb-1 block">Título</label><input type="text" name="title" required placeholder="Escribe un título..." class="w-full bg-darkbg border border-gray-700 rounded-xl p-3 text-sm focus:outline-none focus:border-brand"></div>
                <div><label class="text-xs text-gray-400 font-semibold mb-1 block">Descripción (Opcional)</label><textarea name="description" rows="2" placeholder="Agrega detalles..." class="w-full bg-darkbg border border-gray-700 rounded-xl p-3 text-sm focus:outline-none focus:border-brand resize-none"></textarea></div>
                <div><label class="text-xs text-gray-400 font-semibold mb-1 block">Categoría</label><select name="category" required class="w-full bg-darkbg border border-gray-700 rounded-xl p-3 text-sm focus:outline-none focus:border-brand"><option value="image">🖼️ Imagen</option><option value="video">🎥 Video Largo</option><option value="short">📱 Video Corto (Short)</option></select></div>
                <div><label class="text-xs text-gray-400 font-semibold mb-1 block">Archivo</label><input type="file" name="file" required accept="image/*,video/*" class="w-full text-sm text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-xs file:font-semibold file:bg-brand file:text-white hover:file:bg-rose-600"></div>
                <button type="submit" class="w-full bg-brand hover:bg-rose-600 text-white font-bold py-3 rounded-xl transition mt-2">Publicar</button>
            </form>
        </div>
    </div>

    <script>
        lucide.createIcons();
        let currentMediaId = null;
        let currentAuthorEmail = null;
        let currentRawSrc = '';
        let currentCategory = '';

        function openUploadModal() { document.getElementById('uploadModal').classList.remove('hidden'); }
        function closeUploadModal() { document.getElementById('uploadModal').classList.add('hidden'); }

        function shareMedia(event, id) {
            if(event) event.stopPropagation();
            const shareUrl = window.location.origin + '/?media_id=' + id;
            if (navigator.share) {
                navigator.share({ title: 'Mira este contenido en MediaPro', url: shareUrl }).catch(() => {});
            } else {
                navigator.clipboard.writeText(shareUrl).then(() => { alert('¡Enlace copiado al portapapeles!'); });
            }
        }

        function openModal(id, category, src, title, description, userName, userEmail, likesCount, views, userLiked, userFavorited, comments) {
            currentMediaId = id;
            currentAuthorEmail = userEmail;
            currentRawSrc = src;
            currentCategory = category;

            const modal = document.getElementById('mediaModal');
            const container = document.getElementById('modalMediaContainer');
            
            document.getElementById('modalTitle').innerText = title;
            document.getElementById('modalDescription').innerText = description || 'Sin descripción.';
            document.getElementById('modalCategory').innerText = category;
            document.getElementById('modalViews').innerText = views;
            document.getElementById('txtLikesCount').innerText = likesCount;
            document.getElementById('modalAuthor').innerText = '@' + userName;
            document.getElementById('modalAvatar').innerText = userName[0] || 'U';

            updateLikeBtnUI(userLiked);
            updateFavBtnUI(userFavorited);
            renderComments(comments);

            const fsBtnHTML = `<button onclick="triggerFullscreenPlayer()" class="absolute bottom-4 right-4 bg-black/70 hover:bg-black text-white p-2.5 rounded-xl border border-white/20 backdrop-blur-md opacity-90 hover:opacity-100 transition flex items-center gap-1.5 text-xs font-semibold shadow-lg z-30"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-maximize-2"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" x2="14" y1="3" y2="10"/><line x1="3" x2="10" y1="21" y2="14"/></svg> Pantalla Completa</button>`;

            if (category === 'image') {
                container.innerHTML = `<img src="${src}" class="max-w-full max-h-[80vh] object-contain rounded-lg">` + fsBtnHTML;
            } else {
                container.innerHTML = `<video id="modalVideoPlayer" src="${src}" controls autoplay class="max-w-full max-h-[80vh] object-contain rounded-lg"></video>` + fsBtnHTML;
            }

            modal.classList.add('flex');
            modal.classList.remove('hidden');

            fetch('/api/view/' + id, { method: 'POST' })
                .then(r => r.json())
                .then(data => { if(data.views) document.getElementById('modalViews').innerText = data.views; });
        }

        function closeModal() {
            const modal = document.getElementById('mediaModal');
            const container = document.getElementById('modalMediaContainer');
            const vid = container.querySelector('video');
            if(vid) vid.pause();
            container.innerHTML = '';
            modal.classList.remove('flex');
            modal.classList.add('hidden');
        }

        function triggerFullscreenPlayer() {
            const modalVid = document.getElementById('modalVideoPlayer');
            let currentTime = 0;
            if (modalVid) {
                currentTime = modalVid.currentTime;
                modalVid.pause();
            }

            const overlay = document.getElementById('trueFullscreenOverlay');
            const container = document.getElementById('trueFullscreenContainer');
            if (currentCategory === 'image') {
                container.innerHTML = `<img src="${currentRawSrc}" class="max-w-full max-h-full object-contain">`;
            } else {
                container.innerHTML = `<video id="fsVideoPlayer" src="${currentRawSrc}" controls autoplay class="max-w-full max-h-full object-contain"></video>`;
                const fsVid = document.getElementById('fsVideoPlayer');
                fsVid.currentTime = currentTime;
            }
            overlay.classList.remove('hidden');
        }

        function closeTrueFullscreen() {
            const overlay = document.getElementById('trueFullscreenOverlay');
            const fsVid = document.getElementById('fsVideoPlayer');
            let currentTime = 0;
            if(fsVid) {
                currentTime = fsVid.currentTime;
                fsVid.pause();
            }
            document.getElementById('trueFullscreenContainer').innerHTML = '';
            overlay.classList.add('hidden');

            const modalVid = document.getElementById('modalVideoPlayer');
            if(modalVid) {
                modalVid.currentTime = currentTime;
                modalVid.play();
            }
        }

        function updateLikeBtnUI(liked) {
            const btn = document.getElementById('btnLike');
            const icon = document.getElementById('iconLike');
            if (liked) {
                btn.classList.add('text-rose-500', 'border-rose-500/50');
                icon.classList.add('fill-rose-500');
            } else {
                btn.classList.remove('text-rose-500', 'border-rose-500/50');
                icon.classList.remove('fill-rose-500');
            }
        }

        function updateFavBtnUI(fav) {
            const icon = document.getElementById('iconFav');
            if (fav) {
                icon.classList.add('fill-brand', 'text-brand');
            } else {
                icon.classList.remove('fill-brand', 'text-brand');
            }
        }

        function renderComments(comments) {
            const box = document.getElementById('commentsContainer');
            box.innerHTML = '';
            if(!comments || comments.length === 0) {
                box.innerHTML = '<p class="text-xs text-gray-500">Sé el primero en comentar.</p>';
                return;
            }
            comments.forEach(c => {
                box.innerHTML += `
                    <div class="bg-darkbg p-2.5 rounded-xl border border-gray-800">
                        <span class="text-xs font-bold text-white block">@${c.user_name}</span>
                        <p class="text-xs text-gray-300 mt-0.5">${c.comment_text}</p>
                    </div>
                `;
            });
        }

        function toggleLikeCurrent() {
            if(!currentMediaId) return;
            fetch('/api/like/' + currentMediaId, { method: 'POST' })
                .then(r => {
                    if(r.status === 401) { alert('Debes iniciar sesión con Google.'); return; }
                    return r.json();
                })
                .then(data => {
                    if(data) {
                        document.getElementById('txtLikesCount').innerText = data.likes_count;
                        updateLikeBtnUI(data.liked);
                    }
                });
        }

        function toggleFavCurrent() {
            if(!currentMediaId) return;
            fetch('/api/favorite/' + currentMediaId, { method: 'POST' })
                .then(r => {
                    if(r.status === 401) { alert('Debes iniciar sesión con Google.'); return; }
                    return r.json();
                })
                .then(data => {
                    if(data) updateFavBtnUI(data.favorited);
                });
        }

        function toggleFollowAuthor() {
            if(!currentAuthorEmail) return;
            fetch('/api/follow/' + currentAuthorEmail, { method: 'POST' })
                .then(r => {
                    if(r.status === 401) { alert('Debes iniciar sesión para seguir creadores.'); return; }
                    if(r.status === 400) { alert('No puedes seguirte a ti mismo.'); return; }
                    return r.json();
                })
                .then(data => {
                    if(data) {
                        const btn = document.getElementById('btnFollowModal');
                        if(data.is_following) {
                            btn.innerText = 'Siguiendo';
                            btn.classList.add('bg-brand', 'text-white');
                        } else {
                            btn.innerText = 'Seguir';
                            btn.classList.remove('bg-brand', 'text-white');
                        }
                    }
                });
        }

        function postComment(e) {
            e.preventDefault();
            const input = document.getElementById('inputComment');
            const text = input.value.trim();
            if(!text || !currentMediaId) return;

            const formData = new FormData();
            formData.append('comment_text', text);

            fetch('/api/comment/' + currentMediaId, { method: 'POST', body: formData })
                .then(r => r.json())
                .then(data => {
                    if(data.user_name) {
                        input.value = '';
                        const box = document.getElementById('commentsContainer');
                        if(box.innerText.includes('Sé el primero')) box.innerHTML = '';
                        box.innerHTML = `
                            <div class="bg-darkbg p-2.5 rounded-xl border border-gray-800">
                                <span class="text-xs font-bold text-white block">@${data.user_name}</span>
                                <p class="text-xs text-gray-300 mt-0.5">${data.comment_text}</p>
                            </div>
                        ` + box.innerHTML;
                    }
                });
        }

        document.addEventListener('DOMContentLoaded', function() {
            {% if media_id_param %}
                const card = document.getElementById('card-{{ media_id_param }}');
                if(card) card.click();
            {% endif %}
        });

        document.addEventListener('keydown', function(event) { if (event.key === 'Escape') { closeModal(); closeTrueFullscreen(); closeUploadModal(); } });
    </script>
</body>
</html>
'''

PROFILE_HTML = '''
<!DOCTYPE html>
<html lang="es" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mi Perfil y Panel de Creador</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>tailwind.config = { darkMode: 'class', theme: { extend: { colors: { brand: '#ff3366', darkbg: '#0f0f12', cardbg: '#18181c', hoverbg: '#242429' } } } }</script>
    <script src="https://unpkg.com/lucide@latest"></script>
</head>
<body class="bg-darkbg text-gray-100 font-sans min-h-screen flex flex-col relative">
    <header class="h-16 border-b border-gray-800 bg-cardbg px-6 flex items-center justify-between">
        <a href="/" class="text-xl font-black text-brand tracking-wider">MEDIAPRO</a>
        <a href="/" class="text-sm font-medium bg-hoverbg px-4 py-2 rounded-xl text-gray-300 hover:text-white border border-gray-700">← Volver al Inicio</a>
    </header>

    <div class="max-w-4xl mx-auto w-full px-6 py-10 flex flex-col items-center border-b border-gray-800 text-center">
        <img src="{{ session.user.picture }}" class="w-24 h-24 rounded-full object-cover border-2 border-brand mb-4 shadow-xl">
        <h1 class="text-2xl font-bold text-white">@{{ current_username }}</h1>
        <p class="text-xs text-gray-400 mb-4">{{ session.user.email }}</p>

        <form onsubmit="saveUsername(event)" class="flex items-center gap-2 mb-6 bg-darkbg p-2 rounded-2xl border border-gray-800 max-w-sm w-full">
            <span class="text-xs font-bold text-gray-500 pl-3">@</span>
            <input type="text" id="inputUsername" value="{{ current_username }}" required class="bg-transparent text-xs font-semibold text-white focus:outline-none flex-1" placeholder="Tu Apodo de Creador">
            <button type="submit" class="bg-brand hover:bg-rose-600 text-white text-[10px] font-bold px-3 py-1.5 rounded-xl transition">Guardar Apodo</button>
        </form>

        <div class="flex items-center gap-8 text-center">
            <div>
                <span class="text-xl font-bold text-white block">{{ followers_count }}</span>
                <span class="text-xs text-gray-400 uppercase tracking-wider">Seguidores</span>
            </div>
            <div class="w-px h-8 bg-gray-800"></div>
            <div>
                <span class="text-xl font-bold text-white block">{{ total_views }}</span>
                <span class="text-xs text-gray-400 uppercase tracking-wider">Vistas Totales</span>
            </div>
            <div class="w-px h-8 bg-gray-800"></div>
            <div>
                <span class="text-xl font-bold text-brand block">{{ total_coins }} 🪙</span>
                <span class="text-[10px] text-emerald-400 font-bold block mt-0.5">(~${{ "{:,}".format(estimated_cop) }} COP)</span>
            </div>
        </div>
    </div>

    <div class="max-w-4xl mx-auto w-full px-6 py-8">
        <div class="bg-cardbg rounded-3xl border border-gray-800 p-6 shadow-xl relative overflow-hidden">
            <div class="absolute top-0 right-0 p-6 text-brand/10 pointer-events-none"><i data-lucide="award" class="w-28 h-28"></i></div>
            <h2 class="text-lg font-bold text-white mb-2 flex items-center gap-2"><i data-lucide="zap" class="text-brand"></i> Programa de Monetización de Creadores</h2>
            
            {% if followers_count < 50 %}
                <div class="bg-amber-500/10 border border-amber-500/30 rounded-2xl p-4 mt-4">
                    <p class="text-sm text-amber-300 font-semibold mb-2">⚠️ Te faltan seguidores para activar la monetización</p>
                    <p class="text-xs text-gray-300 mb-3">Requisito: Necesitas al menos <b>50 seguidores</b> (Tienes actualmente {{ followers_count }}/50). ¡Comparte tu contenido para crecer!</p>
                    <div class="w-full bg-darkbg rounded-full h-2.5 overflow-hidden">
                        <div class="bg-amber-500 h-2.5 rounded-full" style="width: {{ (followers_count / 50) * 100 }}%"></div>
                    </div>
                </div>
            {% else %}
                <div class="bg-emerald-500/10 border border-emerald-500/30 rounded-2xl p-4 mt-4 mb-6">
                    <p class="text-sm text-emerald-400 font-bold mb-1">🎉 ¡Programa de Monetización Desbloqueado!</p>
                    <p class="text-xs text-gray-300">A partir de las primeras 100 vistas, 1 vista = 1 moneda. <b>1,000 monedas equivalen a $3.000 COP</b>.</p>
                </div>

                <div class="flex flex-col md:flex-row items-center justify-between gap-4 bg-darkbg p-5 rounded-2xl border border-gray-800">
                    <div>
                        <span class="text-xs text-gray-400 block mb-1">Saldo Disponible para Retiro</span>
                        <span class="text-2xl font-black text-white">{{ total_coins }} 🪙 <span class="text-emerald-400 font-bold text-lg">(${{ "{:,}".format(estimated_cop) }} COP)</span></span>
                    </div>
                    <form onsubmit="requestWithdrawal(event)" class="flex gap-2 w-full md:w-auto">
                        <input type="text" id="inputPaymentInfo" placeholder="Nequi, Daviplata o Banco + Nro" required class="bg-cardbg border border-gray-700 rounded-xl px-4 py-2.5 text-xs text-white focus:outline-none focus:border-brand w-full md:w-64">
                        <button type="submit" class="bg-brand hover:bg-rose-600 text-white font-bold px-5 py-2.5 rounded-xl text-xs transition shadow-lg shrink-0">Solicitar Retiro</button>
                    </form>
                </div>
            {% endif %}

            {% if withdrawals %}
            <h3 class="text-sm font-bold text-gray-400 uppercase tracking-wider mt-8 mb-4">Historial de Solicitudes de Retiro</h3>
            <div class="divide-y divide-gray-800 border border-gray-800 rounded-2xl overflow-hidden bg-darkbg">
                {% for w in withdrawals %}
                <div class="p-4 flex items-center justify-between text-xs">
                    <div>
                        <span class="font-bold text-white block">{{ w.coins }} Monedas (${{ "{:,}".format(w.amount_cop) }} COP)</span>
                        <span class="text-gray-400">Datos: {{ w.payment_info }}</span>
                    </div>
                    <div>
                        <span class="px-3 py-1 rounded-full font-bold {% if w.status == 'Pagado' %}bg-green-500/20 text-green-400{% else %}bg-amber-500/20 text-amber-400{% endif %}">{{ w.status }}</span>
                    </div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
        </div>
    </div>

    <main class="max-w-6xl mx-auto w-full p-6 flex-1">
        <h2 class="text-lg font-bold mb-6 text-white">Mis publicaciones</h2>
        <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
            {% for item in items %}
                <div class="bg-cardbg rounded-2xl overflow-hidden border border-gray-800 flex flex-col">
                    <div class="aspect-video bg-black relative">
                        {% if item.category == 'image' %}<img src="{{ url_for('static', filename='uploads/' + item.filename) }}" class="w-full h-full object-cover">{% else %}<video controls class="w-full h-full object-cover"><source src="{{ url_for('static', filename='uploads/' + item.filename) }}" type="video/mp4"></video>{% endif %}
                        <div class="absolute bottom-2 right-2 bg-black/60 text-white text-[10px] font-bold px-2 py-0.5 rounded">👁️ {{ item.views }}</div>
                    </div>
                    <div class="p-4 flex items-center justify-between">
                        <div class="overflow-hidden"><span class="text-sm font-semibold truncate block text-white">{{ item.title }}</span></div>
                        <form action="/delete/{{ item.id }}" method="POST" onsubmit="return confirm('¿Eliminar publicación?');"><button type="submit" class="bg-red-500/20 text-red-400 hover:bg-red-500 hover:text-white p-2 rounded-xl transition"><i data-lucide="trash-2" class="w-4 h-4"></i></button></form>
                    </div>
                </div>
            {% endfor %}
        </div>
    </main>

    <a href="https://wa.me/573238682789?text=Hola,%20quiero%20reportar%20un%20problema%20en%20la%20plataforma." target="_blank" class="fixed bottom-6 right-6 bg-emerald-500 hover:bg-emerald-600 text-white font-bold p-3.5 rounded-full shadow-2xl flex items-center gap-2 border border-emerald-400/30 transition hover:scale-105 z-50 group">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" class="w-6 h-6"><path d="M.057 24l1.687-6.163c-1.041-1.804-1.588-3.849-1.587-5.946.003-6.556 5.338-11.891 11.893-11.891 3.181.001 6.167 1.24 8.413 3.488 2.245 2.248 3.481 5.236 3.48 8.414-.003 6.557-5.338 11.892-11.893 11.892-1.99-.001-3.951-.5-5.688-1.448l-6.305 1.654zm6.597-3.807c1.676.995 3.276 1.591 5.392 1.592 5.448 0 9.886-4.434 9.889-9.885.002-5.462-4.415-9.89-9.881-9.892-5.452 0-9.887 4.434-9.889 9.884-.001 2.225.651 3.891 1.746 5.634l-.999 3.648 3.742-.981zm11.387-5.464c-.074-.124-.272-.198-.57-.347-.297-.149-1.758-.868-2.031-.967-.272-.099-.47-.149-.669.149-.198.297-.768.967-.941 1.165-.173.198-.347.223-.644.074-.297-.149-1.255-.462-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.297-.347.446-.521.151-.172.2-.296.3-.495.099-.198.05-.372-.025-.521-.075-.148-.669-1.636-.916-2.233-.241-.581-.487-.502-.669-.51l-.57-.01c-.198 0-.52.074-.792.372s-1.04 1.016-1.04 2.479 1.065 2.876 1.213 3.074c.149.198 2.095 3.2 5.076 4.487.709.306 1.263.489 1.694.626.712.226 1.36.194 1.872.118.571-.085 1.758-.719 2.006-1.413.248-.695.248-1.29.173-1.414z"/></svg>
        <span class="text-xs font-bold hidden sm:inline-block pr-1">Reportar problema</span>
    </a>

    <script>
        lucide.createIcons();
        
        function saveUsername(e) {
            e.preventDefault();
            const username = document.getElementById('inputUsername').value.trim();
            if(!username) return;

            const formData = new FormData();
            formData.append('username', username);

            fetch('/api/update-username', { method: 'POST', body: formData })
                .then(r => r.json())
                .then(data => {
                    if(data.status === 'success') {
                        alert('¡Tu Apodo de Creador se actualizó correctamente!');
                        location.reload();
                    }
                });
        }

        function requestWithdrawal(e) {
            e.preventDefault();
            const info = document.getElementById('inputPaymentInfo').value.trim();
            const formData = new FormData();
            formData.append('payment_info', info);

            fetch('/api/withdraw', { method: 'POST', body: formData })
                .then(r => r.json())
                .then(data => {
                    if(data.error === 'not_enough_followers') alert('Necesitas al menos 50 seguidores para retirar.');
                    else if(data.error === 'not_enough_coins') alert('No tienes el mínimo de 1,000 monedas acumuladas.');
                    else if(data.status === 'success') {
                        alert('¡Solicitud enviada! Vas a recibir $' + data.amount_cop.toLocaleString() + ' COP.');
                        location.reload();
                    } else {
                        alert('Ocurrió un error al procesar la solicitud.');
                    }
                });
        }
    </script>
</body>
</html>
'''

SHORTS_FEED_HTML = '''
<!DOCTYPE html>
<html lang="es" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shorts - Feed Deslizable</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        .no-scrollbar::-webkit-scrollbar { display: none; }
        .no-scrollbar { -ms-overflow-style: none; scrollbar-width: none; }
        
        .snap-container { 
            scroll-snap-type: y mandatory; 
            overflow-y: scroll; 
            height: calc(100vh - 4rem); 
            scroll-behavior: smooth;
        }
        .snap-item { 
            scroll-snap-align: start; 
            height: calc(100vh - 4rem); 
            display: flex; 
            align-items: center; 
            justify-content: center; 
        }
        
        @keyframes popHeart { 0% { transform: scale(0); opacity: 1; } 50% { transform: scale(1.3); opacity: 1; } 100% { transform: scale(1); opacity: 0; } }
        .heart-animation { animation: popHeart 0.8s ease-out forwards; }
    </style>
</head>
<body class="bg-black text-gray-100 font-sans overflow-hidden flex flex-col h-screen">

    <header class="h-16 border-b border-gray-800 bg-[#18181c]/90 backdrop-blur-md px-6 flex items-center justify-between shrink-0 z-40">
        <div class="flex items-center gap-4">
            <a href="/" class="flex items-center gap-2 text-xl font-black text-[#ff3366] tracking-wider">
                <i data-lucide="play-circle" class="w-8 h-8 fill-[#ff3366] text-black"></i>
                <span>MEDIA<span class="text-white">PRO</span></span>
            </a>
        </div>
        <div class="flex items-center gap-3">
            <a href="/?category=all" class="text-xs bg-gray-800 hover:bg-gray-700 text-white font-semibold px-4 py-2 rounded-full transition flex items-center gap-1.5">
                <i data-lucide="arrow-left" class="w-4 h-4"></i> Salir de Shorts
            </a>
        </div>
    </header>

    <div class="snap-container no-scrollbar relative w-full flex-1">
        <div class="snap-item w-full relative bg-black">
            <div class="relative h-[85vh] aspect-[9/16] bg-gradient-to-br from-rose-950 to-neutral-900 rounded-3xl overflow-hidden shadow-2xl flex flex-col items-center justify-center border border-rose-500/30 p-8 text-center">
                <span class="absolute top-6 bg-rose-500 text-white text-[10px] font-bold px-3 py-1 rounded-full uppercase tracking-widest shadow">Patrocinado</span>
                <i data-lucide="zap" class="w-16 h-16 text-rose-400 mb-4 animate-bounce"></i>
                <h3 class="text-2xl font-black text-white mb-3">¡Descubre ofertas increíbles aquí!</h3>
                <p class="text-sm text-gray-300 mb-6">Explora contenido exclusivo de nuestros patrocinadores y apoya la plataforma.</p>
                <a href="#" onclick="alert('Publicidad de Shorts'); return false;" class="bg-[#ff3366] text-white font-bold py-3 px-8 rounded-2xl text-sm shadow-xl hover:bg-rose-600 transition">Visitar Sitio</a>
            </div>
        </div>

        {% for item in items %}
            <div class="snap-item w-full relative bg-black">
                <div class="relative h-[85vh] aspect-[9/16] bg-neutral-900 rounded-3xl overflow-hidden shadow-2xl flex items-center justify-center border border-gray-800" onclick="handleTap(event, {{ item.id }}, this)">
                    
                    <video src="{{ url_for('static', filename='uploads/' + item.filename) }}" class="w-full h-full object-cover cursor-pointer short-video" loop data-id="{{ item.id }}"></video>
                    
                    <div class="heart-overlay absolute pointer-events-none hidden text-rose-500 drop-shadow-lg">
                        <i data-lucide="heart" class="w-24 h-24 fill-rose-500"></i>
                    </div>

                    <div class="absolute bottom-4 left-4 right-16 z-20 pointer-events-none drop-shadow-md">
                        <div class="flex items-center gap-3 mb-2">
                            <div class="w-10 h-10 rounded-full bg-[#ff3366] flex items-center justify-center font-bold text-white text-sm shadow">{{ item.user_name[0] }}</div>
                            <span class="font-bold text-white text-sm">@{{ item.user_name }}</span>
                        </div>
                        <h3 class="font-bold text-white text-sm mb-1">{{ item.title }}</h3>
                        {% if item.description %}<p class="text-xs text-gray-200 line-clamp-2">{{ item.description }}</p>{% endif %}
                    </div>

                    <div class="absolute right-3 bottom-12 flex flex-col items-center gap-5 z-20">
                        <button onclick="toggleShortLike(event, {{ item.id }}, this)" class="flex flex-col items-center gap-1 text-white">
                            <div class="w-10 h-10 rounded-full bg-black/50 backdrop-blur-md flex items-center justify-center border border-white/10 {% if item.user_liked %}text-rose-500{% endif %}">
                                <i data-lucide="heart" class="w-5 h-5 {% if item.user_liked %}fill-rose-500{% endif %}"></i>
                            </div>
                            <span class="text-[10px] font-bold likes-count">{{ item.likes_count }}</span>
                        </button>

                        <button onclick="shareShort(event, {{ item.id }})" class="flex flex-col items-center gap-1 text-white">
                            <div class="w-10 h-10 rounded-full bg-black/50 backdrop-blur-md flex items-center justify-center border border-white/10 hover:border-white/40 transition">
                                <i data-lucide="share-2" class="w-5 h-5"></i>
                            </div>
                            <span class="text-[10px] font-bold">Share</span>
                        </button>
                        
                        <div class="flex flex-col items-center gap-1 text-white">
                            <div class="w-10 h-10 rounded-full bg-black/50 backdrop-blur-md flex items-center justify-center border border-white/10">
                                <i data-lucide="eye" class="w-5 h-5"></i>
                            </div>
                            <span class="text-[10px] font-bold short-views">{{ item.views }}</span>
                        </div>
                    </div>
                </div>
            </div>
        {% endfor %}
    </div>

    <script>
        lucide.createIcons();
        let lastTap = 0;

        function shareShort(e, id) {
            e.stopPropagation();
            const shareUrl = window.location.origin + '/?media_id=' + id;
            if (navigator.share) {
                navigator.share({ title: 'Mira este Short en MediaPro', url: shareUrl }).catch(() => {});
            } else {
                navigator.clipboard.writeText(shareUrl).then(() => { alert('¡Enlace copiado al portapapeles!'); });
            }
        }

        function handleTap(event, mediaId, container) {
            const currentTime = new Date().getTime();
            const tapLength = currentTime - lastTap;
            const video = container.querySelector('video');

            if (tapLength < 300 && tapLength > 0) {
                showHeartAnim(container);
                fetch('/api/like/' + mediaId, { method: 'POST' })
                    .then(r => r.json())
                    .then(data => {
                        if(data.likes_count !== undefined) {
                            const btn = container.querySelector('button');
                            btn.querySelector('.likes-count').innerText = data.likes_count;
                            const icon = btn.querySelector('i');
                            if(data.liked) {
                                icon.classList.add('fill-rose-500', 'text-rose-500');
                            } else {
                                icon.classList.remove('fill-rose-500', 'text-rose-500');
                            }
                        }
                    });
            } else {
                if (video.paused) video.play(); else video.pause();
            }
            lastTap = currentTime;
        }

        function showHeartAnim(container) {
            const heart = container.querySelector('.heart-overlay');
            heart.classList.remove('hidden');
            heart.classList.add('heart-animation');
            setTimeout(() => {
                heart.classList.add('hidden');
                heart.classList.remove('heart-animation');
            }, 800);
        }

        function toggleShortLike(e, mediaId, btn) {
            e.stopPropagation();
            fetch('/api/like/' + mediaId, { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    if(data.likes_count !== undefined) {
                        btn.querySelector('.likes-count').innerText = data.likes_count;
                        const icon = btn.querySelector('i');
                        if(data.liked) {
                            icon.classList.add('fill-rose-500', 'text-rose-500');
                        } else {
                            icon.classList.remove('fill-rose-500', 'text-rose-500');
                        }
                    }
                });
        }

        document.addEventListener("DOMContentLoaded", function() {
            const videos = document.querySelectorAll(".short-video");
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    const video = entry.target;
                    if (entry.isIntersecting) {
                        video.play().catch(e => {});
                        const mediaId = video.getAttribute('data-id');
                        if(mediaId) fetch('/api/view/' + mediaId, { method: 'POST' });
                    } else {
                        video.pause();
                        video.currentTime = 0;
                    }
                });
            }, { threshold: 0.6 });
            videos.forEach(video => observer.observe(video));
        });
    </script>
</body>
</html>
'''

ADMIN_MASTER_HTML = '''
<!DOCTYPE html>
<html lang="es" class="dark">
<head>
    <meta charset="UTF-8"><title>Panel Secreto de Administración</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>tailwind.config = { darkMode: 'class', theme: { extend: { colors: { brand: '#ff3366', darkbg: '#0f0f12', cardbg: '#18181c', hoverbg: '#242429' } } } }</script>
    <script src="https://unpkg.com/lucide@latest"></script>
</head>
<body class="bg-darkbg text-gray-100 font-sans min-h-screen flex flex-col">
    <header class="h-16 border-b border-gray-800 bg-cardbg px-6 flex items-center justify-between">
        <span class="text-xl font-black text-red-500">🛡️ PANEL DE ADMINISTRADOR SECRETO</span>
        <a href="/" class="text-sm font-medium bg-hoverbg px-4 py-2 rounded-xl text-gray-300 hover:text-white border border-gray-700">← Ir al sitio público</a>
    </header>
    <main class="max-w-7xl mx-auto w-full p-6 flex-1 flex flex-col gap-10">
        <div>
            <h2 class="text-lg font-bold mb-4 flex items-center gap-2 text-brand"><i data-lucide="dollar-sign"></i> Solicitudes de Retiro de Creadores ({{ withdrawals|length }})</h2>
            <div class="bg-cardbg rounded-2xl border border-gray-800 overflow-hidden">
                <table class="w-full text-left border-collapse text-sm">
                    <thead>
                        <tr class="border-b border-gray-800 bg-hoverbg/50 text-xs uppercase text-gray-400">
                            <th class="p-4">Usuario</th><th class="p-4">Monedas</th><th class="p-4">Monto a Pagar (COP)</th><th class="p-4">Datos de Pago (Nequi / Banco)</th><th class="p-4">Estado</th><th class="p-4">Acción</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800">
                        {% for w in withdrawals %}
                        <tr class="hover:bg-hoverbg/30">
                            <td class="p-4 font-semibold text-white">@{{ w.user_name }}<br><span class="text-xs text-gray-400">{{ w.user_email }}</span></td>
                            <td class="p-4 font-bold text-brand">{{ w.coins }} Monedas</td>
                            <td class="p-4 font-black text-emerald-400">${{ "{:,}".format(w.amount_cop) }} COP</td>
                            <td class="p-4 font-mono text-gray-300">{{ w.payment_info }}</td>
                            <td class="p-4"><span class="px-3 py-1 rounded-full text-xs font-bold {% if w.status == 'Pagado' %}bg-green-500/20 text-green-400{% else %}bg-amber-500/20 text-amber-400{% endif %}">{{ w.status }}</span></td>
                            <td class="p-4">
                                {% if w.status != 'Pagado' %}
                                <form action="/admin/pay-withdrawal/{{ w.id }}" method="POST" onsubmit="return confirm('¿Confirmas que ya realizaste la transferencia de ${{ w.amount_cop }} COP?');">
                                    <button type="submit" class="bg-green-500/20 hover:bg-green-500 text-green-400 hover:text-white px-3 py-1.5 rounded-xl text-xs font-semibold transition">Marcar Pagado</button>
                                </form>
                                {% else %}
                                <span class="text-xs text-gray-500">Completado</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% if not withdrawals %}<div class="p-8 text-center text-gray-500">No hay solicitudes de retiro pendientes.</div>{% endif %}
            </div>
        </div>

        <div>
            <h2 class="text-lg font-bold mb-4 flex items-center gap-2"><i data-lucide="database" class="text-brand"></i> Todo el Contenido Publicado ({{ items|length }})</h2>
            <div class="bg-cardbg rounded-2xl border border-gray-800 overflow-hidden">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-gray-800 bg-hoverbg/50 text-xs uppercase text-gray-400">
                            <th class="p-4">ID</th><th class="p-4">Contenido</th><th class="p-4">Título y Descripción</th><th class="p-4">Autor</th><th class="p-4">Acciones</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800 text-sm">
                        {% for item in items %}
                        <tr class="hover:bg-hoverbg/30 transition">
                            <td class="p-4 text-gray-500 font-mono">#{{ item.id }}</td>
                            <td class="p-4 w-52">
                                <div class="w-44 h-24 bg-black rounded-xl overflow-hidden border border-gray-700 shadow-md">
                                    {% if item.category == 'image' %}
                                        <img src="{{ url_for('static', filename='uploads/' + item.filename) }}" class="w-full h-full object-cover">
                                    {% else %}
                                        <video controls class="w-full h-full object-cover"><source src="{{ url_for('static', filename='uploads/' + item.filename) }}" type="video/mp4"></video>
                                    {% endif %}
                                </div>
                            </td>
                            <td class="p-4">
                                <div class="font-semibold text-white">{{ item.title }}</div>
                                {% if item.description %}<div class="text-xs text-gray-400 mt-0.5 line-clamp-2">{{ item.description }}</div>{% endif %}
                                <span class="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-hoverbg text-gray-400 inline-block mt-1.5">{{ item.category }}</span>
                            </td>
                            <td class="p-4">
                                <div class="flex items-center gap-2">
                                    <div class="w-6 h-6 rounded-full bg-gray-700 flex items-center justify-center font-bold text-xs">{{ item.user_name[0] }}</div>
                                    <span class="font-medium text-gray-300">@{{ item.user_name }}</span>
                                    {% if item.user_name in banned_names %}<span class="bg-red-500/20 text-red-400 text-[10px] font-bold px-1.5 py-0.5 rounded">BANEADO</span>{% endif %}
                                </div>
                            </td>
                            <td class="p-4 flex items-center gap-2">
                                <form action="/admin/delete-media/{{ item.id }}" method="POST" onsubmit="return confirm('¿Eliminar contenido?');">
                                    <button type="submit" class="bg-red-500/20 hover:bg-red-500 text-red-400 hover:text-white px-3 py-1.5 rounded-xl text-xs font-semibold transition flex items-center gap-1"><i data-lucide="trash-2" class="w-3.5 h-3.5"></i> Borrar</button>
                                </form>
                                {% if item.user_name not in banned_names %}
                                    <form action="/admin/ban-user" method="POST" onsubmit="return confirm('¿Banear usuario?');">
                                        <input type="hidden" name="user_name" value="{{ item.user_name }}">
                                        <button type="submit" class="bg-amber-500/20 hover:bg-amber-500 text-amber-400 hover:text-white px-3 py-1.5 rounded-xl text-xs font-semibold transition flex items-center gap-1"><i data-lucide="user-x" class="w-3.5 h-3.5"></i> Banear</button>
                                    </form>
                                {% else %}
                                    <form action="/admin/unban-user" method="POST">
                                        <input type="hidden" name="user_name" value="{{ item.user_name }}">
                                        <button type="submit" class="bg-green-500/20 hover:bg-green-500 text-green-400 hover:text-white px-3 py-1.5 rounded-xl text-xs font-semibold transition flex items-center gap-1"><i data-lucide="user-check" class="w-3.5 h-3.5"></i> Desbanear</button>
                                    </form>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% if not items %}<div class="p-8 text-center text-gray-500">No hay contenido registrado.</div>{% endif %}
            </div>
        </div>
    </main>
    <script>lucide.createIcons();</script>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)