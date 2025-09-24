from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import yaml
from datetime import date, datetime
import pandas as pd
from io import StringIO
import MySQLdb.cursors
from functools import wraps

# =========================================================================
# 1. Configuración de la aplicación y la base de datos
# =========================================================================
app = Flask(__name__)

# Configuración de la base de datos desde db.yaml
try:
    with open('db.yaml', 'r') as file:
        db = yaml.safe_load(file)
    app.config['MYSQL_HOST'] = db['mysql_host']
    app.config['MYSQL_USER'] = db['mysql_user']
    app.config['MYSQL_PASSWORD'] = db['mysql_password']
    app.config['MYSQL_DB'] = db['mysql_db']
    mysql = MySQL(app)
except FileNotFoundError:
    print("Error: El archivo db.yaml no se encontró. Asegúrate de que esté en la misma carpeta que app.py.")
    exit()

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# =========================================================================
# 2. Funcionalidades del Sistema de Login
# =========================================================================
# Decorador para restringir el acceso por rol
def rol_requerido(rol_esperado):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.rol != rol_esperado:
                flash('No tienes permiso para acceder a esta página.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class User(UserMixin):
    """Modelo de Usuario para Flask-Login con rol."""
    def __init__(self, id, usuario, password, rol):
        self.id = id
        self.usuario = usuario
        self.password = password
        self.rol = rol

@login_manager.user_loader
def load_user(user_id):
    """Carga un usuario desde la base de datos."""
    with mysql.connection.cursor() as cursor:
        cursor.execute("SELECT id, usuario, password, rol FROM usuarios WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[3])
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Ruta para el inicio de sesión."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        usuario = request.form['usuario']
        password = request.form['password']
        
        with mysql.connection.cursor() as cursor:
            # La consulta ahora selecciona la columna 'rol'
            cursor.execute("SELECT id, usuario, password, rol FROM usuarios WHERE usuario = %s", (usuario,))
            user_data = cursor.fetchone()
        
        if user_data and check_password_hash(user_data[2], password):
            # Ahora el objeto User se crea con los 4 argumentos
            user = User(user_data[0], user_data[1], user_data[2], user_data[3])
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Credenciales incorrectas. Inténtalo de nuevo.')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Ruta para cerrar la sesión."""
    logout_user()
    return redirect(url_for('login'))

@app.route('/crear_admin')
@login_required
@rol_requerido('admin')
def crear_admin():
    """Ruta para crear el primer usuario administrador."""
    password_hash = generate_password_hash('admin123')
    try:
        with mysql.connection.cursor() as cursor:
            cursor.execute("INSERT INTO usuarios (usuario, password, rol) VALUES (%s, %s, %s)", ('admin', password_hash, 'admin'))
            mysql.connection.commit()
            flash('Usuario administrador creado exitosamente!')
    except Exception:
        flash('El usuario admin ya existe.')
    return redirect(url_for('login'))

# =========================================================================
# 3. Funcionalidades del Sistema de Asistencia
# =========================================================================
@app.route('/')
@login_required
def index():
    """Ruta de inicio (dashboard con estadísticas)."""
    with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cursor:
        # 1. Total de eventos
        cursor.execute("SELECT COUNT(*) as count FROM eventos")
        total_eventos = cursor.fetchone()['count'] if cursor.rowcount > 0 else 0

        # 2. Total de miembros
        cursor.execute("SELECT COUNT(*) as count FROM miembros")
        total_miembros = cursor.fetchone()['count'] if cursor.rowcount > 0 else 0

        # 3. Ausencias por miembro (Top 5)
        cursor.execute("""
            SELECT m.nombres, m.apellidos, COUNT(a.asistio) AS total_ausencias
            FROM miembros m
            JOIN asistencia a ON m.dni = a.miembro_dni
            WHERE a.asistio = FALSE
            GROUP BY m.dni
            ORDER BY total_ausencias DESC
            LIMIT 5
        """)
        top_ausencias = cursor.fetchall()
        
        # 4. Asistencia promedio
        cursor.execute("""
            SELECT AVG(attendees) as promedio FROM (
                SELECT COUNT(asistio) AS attendees
                FROM asistencia
                WHERE asistio = TRUE
                GROUP BY evento_id
            ) AS subquery
        """)
        asistencia_promedio_raw = cursor.fetchone()['promedio'] if cursor.rowcount > 0 else None
        asistencia_promedio = f"{asistencia_promedio_raw:.2f}" if asistencia_promedio_raw is not None else "0.00"

    # Calcular participación total (%)
    if total_miembros > 0:
        participacion_total = ((total_miembros - len(top_ausencias)) / total_miembros) * 100
    else:
        participacion_total = 0

    return render_template('index.html', 
                           total_eventos=total_eventos, 
                           total_miembros=total_miembros, 
                           top_ausencias=top_ausencias, 
                           asistencia_promedio=asistencia_promedio,
                           participacion_total=f"{participacion_total:.2f}")

# RUTA PARA MOSTRAR EL FORMULARIO DE ASISTENCIA (POR DNI)
@app.route('/asistencia_form', methods=['GET'])
@login_required
def asistencia_form():
    """Muestra el formulario para registrar asistencia por DNI."""
    with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cursor:
        cursor.execute("SELECT id, nombre, fecha FROM eventos")
        eventos = cursor.fetchall()
    
    return render_template('asistencia.html', eventos=eventos)

# RUTA PARA CONFIRMAR ASISTENCIA DESPUÉS DE LA BÚSQUEDA POR DNI
@app.route('/confirmar_asistencia/<dni>/<evento_id>/<tipo_registro>', methods=['GET', 'POST'])
@login_required
def confirmar_asistencia(dni, evento_id, tipo_registro):
    """Valida el DNI y registra la entrada/salida."""
    with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cursor:
        # Obtiene los datos del evento
        cursor.execute("SELECT id, nombre, fecha FROM eventos WHERE id = %s", (evento_id,))
        evento = cursor.fetchone()
        
        # Busca al miembro por DNI y sus datos
        cursor.execute("SELECT dni, nombres, apellidos FROM miembros WHERE dni = %s", (dni,))
        miembro = cursor.fetchone()

        if not miembro:
            flash('DNI no encontrado.', 'danger')
            return redirect(url_for('asistencia_form'))
            
        if request.method == 'POST':
            # Lógica para evitar registros duplicados de entrada
            cursor.execute("SELECT COUNT(*) as count FROM asistencia WHERE miembro_dni = %s AND evento_id = %s AND tipo_registro = 'entrada'", (dni, evento_id))
            if cursor.fetchone()['count'] > 0 and tipo_registro == 'entrada':
                flash(f'El miembro {miembro["nombres"]} ya registró su entrada para este evento.', 'warning')
                return redirect(url_for('asistencia_form'))
            
            # Capturar la hora actual del registro y el ID del usuario
            hora_registro = datetime.now()
            registrador_id = current_user.id
            
            # Insertar el nuevo registro
            cursor.execute("INSERT INTO asistencia (miembro_dni, evento_id, asistio, tipo_registro, fecha_registro, usuario_id) VALUES (%s, %s, TRUE, %s, %s, %s)", (dni, evento_id, tipo_registro, hora_registro, registrador_id))
            mysql.connection.commit()
            
            flash(f'Registro de {miembro["nombres"]} ({tipo_registro}) exitoso para el evento {evento["nombre"]}.', 'success')
            return redirect(url_for('asistencia_form'))

    return render_template('confirmar_asistencia.html', miembro=miembro, evento=evento, tipo_registro=tipo_registro)


@app.route('/registrar_asistencia', methods=['POST'])
@login_required
def registrar_asistencia():
    """Procesa el formulario y guarda la asistencia en la base de datos."""
    evento_id = request.form['evento_id']
    miembros_asistentes = request.form.getlist('asistio')
    
    hora_registro = datetime.now()
    registrador_id = current_user.id

    with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cursor:
        # Obtener todos los DNI de los miembros
        cursor.execute("SELECT dni FROM miembros")
        todos_miembros = [m['dni'] for m in cursor.fetchall()]

        # Insertar la asistencia de los presentes
        for dni in miembros_asistentes:
            cursor.execute("INSERT INTO asistencia (miembro_dni, evento_id, asistio, fecha_registro, usuario_id) VALUES (%s, %s, TRUE, %s, %s)", (dni, evento_id, hora_registro, registrador_id))
        
        # Insertar la ausencia de los que no fueron marcados
        miembros_ausentes = [dni for dni in todos_miembros if dni not in miembros_asistentes]
        for dni in miembros_ausentes:
            cursor.execute("INSERT INTO asistencia (miembro_dni, evento_id, asistio, fecha_registro, usuario_id) VALUES (%s, %s, FALSE, %s, %s)", (dni, evento_id, hora_registro, registrador_id))

        mysql.connection.commit()
    
    flash('Asistencia registrada exitosamente.')
    return redirect(url_for('asistencia_form'))

@app.route('/reportes')
@login_required
def reportes():
    """Genera y muestra los reportes de asistencia."""
    with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cursor:
        # Reporte 1: Total de ausencias por miembro
        cursor.execute("""
            SELECT m.nombres, m.apellidos, COUNT(a.asistio) AS total_ausencias
            FROM miembros m
            JOIN asistencia a ON m.dni = a.miembro_dni
            WHERE a.asistio = FALSE
            GROUP BY m.dni
            ORDER BY total_ausencias DESC
        """)
        reporte_ausencias = cursor.fetchall()
        
        # Reporte 2: Asistencia por evento
        cursor.execute("""
            SELECT e.nombre, e.fecha, 
                   SUM(CASE WHEN a.asistio = TRUE THEN 1 ELSE 0 END) AS presentes,
                   SUM(CASE WHEN a.asistio = FALSE THEN 1 ELSE 0 END) AS ausentes
            FROM eventos e
            JOIN asistencia a ON e.id = a.evento_id
            GROUP BY e.id
            ORDER BY e.fecha DESC
        """)
        reporte_asistencia_evento = cursor.fetchall()
    
    return render_template('reportes.html',
                           reporte_ausencias=reporte_ausencias,
                           reporte_asistencia_evento=reporte_asistencia_evento)


@app.route('/crear_evento', methods=['GET', 'POST'])
@login_required
@rol_requerido('admin')
def crear_evento():
    """Muestra el formulario y procesa la creación de un nuevo evento."""
    if request.method == 'POST':
        nombre = request.form['nombre']
        fecha = request.form['fecha']
        tipo_evento = request.form['tipo_evento']
        
        try:
            with mysql.connection.cursor() as cursor:
                cursor.execute("INSERT INTO eventos (nombre, fecha, tipo_evento) VALUES (%s, %s, %s)", (nombre, fecha, tipo_evento))
                mysql.connection.commit()
            flash('Evento creado exitosamente.', 'success')
        except Exception as e:
            flash(f'Error al crear el evento: {str(e)}', 'error')
        
        return redirect(url_for('crear_evento'))
    
    return render_template('crear_evento.html')

@app.route('/crear_miembro', methods=['GET', 'POST'])
@login_required
@rol_requerido('admin')
def crear_miembro():
    """Muestra el formulario y procesa la creación de un nuevo miembro."""
    if request.method == 'POST':
        dni = request.form['dni']
        nombres = request.form['nombres']
        apellidos = request.form['apellidos']
        sexo = request.form['sexo']
        edad = request.form['edad']
        estado_civil = request.form['estado_civil']
        fecha_nacimiento = request.form['fecha_nacimiento']
        carga_familiar = request.form.get('carga_familiar', 0)
        
        try:
            with mysql.connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO miembros (dni, nombres, apellidos, sexo, edad, estado_civil, fecha_nacimiento, carga_familiar) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (dni, nombres, apellidos, sexo, edad, estado_civil, fecha_nacimiento, carga_familiar))
                mysql.connection.commit()
            flash('Miembro creado exitosamente.', 'success')
        except Exception as e:
            flash(f'Error al crear el miembro: {str(e)}', 'error')
        
        return redirect(url_for('crear_miembro'))
    
    return render_template('crear_miembro.html')

@app.route('/miembros')
@login_required
def miembros_list():
    """Muestra una lista de todos los miembros."""
    with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cursor:
        cursor.execute("SELECT dni, nombres, apellidos, edad, sexo FROM miembros ORDER BY apellidos, nombres")
        miembros = cursor.fetchall()
    
    return render_template('miembros_list.html', miembros=miembros)

@app.route('/cargar_miembros', methods=['GET', 'POST'])
@login_required
@rol_requerido('admin')
def cargar_miembros():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No se seleccionó ningún archivo.', 'danger')
            return redirect(url_for('cargar_miembros'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No se seleccionó ningún archivo.', 'danger')
            return redirect(url_for('cargar_miembros'))
        
        if file:
            try:
                # Lee el archivo CSV o Excel
                if file.filename.endswith('.xlsx'):
                    df = pd.read_excel(file)
                else: # Asumimos CSV
                    data_str = file.read().decode('utf-8')
                    df = pd.read_csv(StringIO(data_str))

                # Renombra las columnas de forma segura
                df.columns = df.columns.str.strip().str.replace('"', '').str.replace('.', '', regex=False).str.replace(' ', '_').str.lower()

                # Combina las columnas de sexo en una sola 'sexo'
                if 'sexo_f' in df.columns and 'sexo_m' in df.columns:
                    df['sexo'] = df.apply(
                        lambda row: 'F' if pd.notna(row['sexo_f']) else ('M' if pd.notna(row['sexo_m']) else None), axis=1
                    )
                else:
                    df['sexo'] = None

                # Procesa las fechas de manera segura
                df['dia'] = pd.to_numeric(df['dia'].astype(str).str.strip(), errors='coerce').fillna(1).astype(int)
                df['mes'] = pd.to_numeric(df['mes'].astype(str).str.strip(), errors='coerce').fillna(1).astype(int)
                df['anio'] = pd.to_numeric(df['anio'].astype(str).str.strip(), errors='coerce').fillna(1900).astype(int)
                
                df['fecha_nacimiento'] = pd.to_datetime(
                    df[['anio', 'mes', 'dia']].astype(str).agg('-'.join, axis=1), 
                    errors='coerce'
                )

                # Limpia y procesa el resto de los datos
                df['carga_familiar'] = pd.to_numeric(df['carga_familiar'].astype(str).str.strip(), errors='coerce').fillna(0).astype(int)
                df['edad'] = pd.to_numeric(df['edad'].astype(str).str.strip(), errors='coerce').fillna(0).astype(int)
                df['dni'] = df['dni'].astype(str).str.strip()
                df.rename(columns={'nombres_y_apellidos': 'nombre_completo'}, inplace=True)
                
                # Divide el nombre completo en nombres y apellidos
                df['apellidos'] = df['nombre_completo'].apply(lambda x: ' '.join(str(x).split(' ')[:-1]) if pd.notna(x) else None)
                df['nombres'] = df['nombre_completo'].apply(lambda x: str(x).split(' ')[-1] if pd.notna(x) else None)

                # Inserta los datos en la base de datos
                with mysql.connection.cursor() as cursor:
                    for _, row in df.iterrows():
                        try:
                            cursor.execute("""
                                INSERT INTO miembros (dni, nombres, apellidos, sexo, edad, estado_civil, fecha_nacimiento, carga_familiar) 
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """, (
                                row['dni'],
                                row['nombres'],
                                row['apellidos'],
                                row['sexo'],
                                row['edad'],
                                row['estado_civil'],
                                row['fecha_nacimiento'],
                                row['carga_familiar']
                            ))
                        except Exception as e:
                            print(f"Error al insertar el miembro con DNI {row['dni']}: {str(e)}")
                            mysql.connection.rollback()
                            continue
                
                mysql.connection.commit()
                flash(f'Se cargaron {len(df)} miembros exitosamente.', 'success')
                return redirect(url_for('miembros_list'))
            except Exception as e:
                flash(f'Error al procesar el archivo: {str(e)}. Asegúrate de que el formato sea correcto.', 'danger')
                return redirect(url_for('cargar_miembros'))

    return render_template('cargar_miembros.html')

# Nueva ruta para procesar la asistencia y redirigir
@app.route('/procesar_asistencia', methods=['POST'])
@login_required
def procesar_asistencia():
    dni = request.form['dni']
    evento_id = request.form['evento_id']
    tipo_registro = request.form['tipo_registro']
    
    return redirect(url_for('confirmar_asistencia', dni=dni, evento_id=evento_id, tipo_registro=tipo_registro))

@app.route('/eventos')
@login_required
def eventos_list():
  with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cursor:
    cursor.execute("SELECT id, nombre, fecha, tipo_evento FROM eventos ORDER BY fecha DESC")
    eventos = cursor.fetchall()
 
  return render_template('eventos_list.html', eventos=eventos)

@app.route('/editar_miembro/<dni>', methods=['GET', 'POST'])
@login_required
@rol_requerido('admin')
def editar_miembro(dni):
  with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cursor:
    # 1. Obtener los datos del miembro por su DNI
    cursor.execute("SELECT * FROM miembros WHERE dni = %s", (dni,))
    miembro = cursor.fetchone()

    if not miembro:
      flash('Miembro no encontrado.', 'danger')
      return redirect(url_for('miembros_list'))

    if request.method == 'POST':
      # 2. Tomar los datos actualizados del formulario
      nombres = request.form['nombres']
      apellidos = request.form['apellidos']
      sexo = request.form['sexo']
      edad = request.form['edad']
      estado_civil = request.form['estado_civil']
      fecha_nacimiento = request.form['fecha_nacimiento']
      carga_familiar = request.form.get('carga_familiar', 0)

      # 3. Ejecutar la consulta de actualización (UPDATE)
      try:
        cursor.execute("""
          UPDATE miembros
          SET nombres = %s, apellidos = %s, sexo = %s, edad = %s, estado_civil = %s, fecha_nacimiento = %s, carga_familiar = %s
          WHERE dni = %s
        """, (nombres, apellidos, sexo, edad, estado_civil, fecha_nacimiento, carga_familiar, dni))
        mysql.connection.commit()
        flash('Miembro actualizado exitosamente.', 'success')
        return redirect(url_for('miembros_list'))
      except Exception as e:
        flash(f'Error al actualizar el miembro: {str(e)}', 'error')

  # Si es un GET request, renderizar el formulario con los datos del miembro
  return render_template('editar_miembro.html', miembro=miembro)

@app.route('/detalle_evento/<evento_id>')
@login_required
def detalle_evento(evento_id):
  """Muestra el detalle de asistencia de un evento en particular."""
  with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cursor:
    # Obtener los datos del evento
    cursor.execute("SELECT id, nombre, fecha FROM eventos WHERE id = %s", (evento_id,))
    evento = cursor.fetchone()

    # Obtener los registros de asistencia para el evento, incluyendo el usuario que lo registró
    cursor.execute("""
      SELECT 
        m.nombres, 
        m.apellidos, 
        a.tipo_registro, 
        a.fecha_registro,
        u.usuario AS usuario_registro
      FROM asistencia a
      JOIN miembros m ON a.miembro_dni = m.dni
      JOIN usuarios u ON a.usuario_id = u.id
      WHERE a.evento_id = %s
      ORDER BY a.fecha_registro ASC
    """, (evento_id,))
    registros_asistencia = cursor.fetchall()
    
  if not evento:
    flash("Evento no encontrado.", "danger")
    return redirect(url_for('eventos_list'))

  return render_template('detalle_evento.html', evento=evento, registros=registros_asistencia)


# Ruta para la gestión de roles de usuarios
# Ruta para la gestión de roles de usuarios con funcionalidad de búsqueda
@app.route('/gestion_roles', methods=['GET', 'POST'])
@login_required
@rol_requerido('admin')
def gestion_roles():
    with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cursor:
        if request.method == 'POST':
            try:
                # Actualizar el rol de cada usuario
                for key, value in request.form.items():
                    if key.startswith('rol_'):
                        user_id = key.split('_')[1]
                        nuevo_rol = value
                        cursor.execute("UPDATE usuarios SET rol = %s WHERE id = %s", (nuevo_rol, user_id))
                mysql.connection.commit()
                flash('Roles actualizados exitosamente.', 'success')
            except Exception as e:
                mysql.connection.rollback()
                flash(f'Error al actualizar roles: {str(e)}', 'danger')
        
        # Lógica de búsqueda para la solicitud GET
        search_query = request.args.get('query', '')
        if search_query:
            search_pattern = f"%{search_query}%"
            cursor.execute("SELECT id, usuario, rol FROM usuarios WHERE usuario LIKE %s", (search_pattern,))
        else:
            cursor.execute("SELECT id, usuario, rol FROM usuarios")
            
        usuarios = cursor.fetchall()
        
    return render_template('gestion_roles.html', usuarios=usuarios, search_query=search_query)


# Nueva ruta para crear una cuenta de usuario a partir de un miembro
@app.route('/crear_usuario_miembro/<dni>', methods=['GET', 'POST'])
@login_required
@rol_requerido('admin')
def crear_usuario_miembro(dni):
    with mysql.connection.cursor(MySQLdb.cursors.DictCursor) as cursor:
        cursor.execute("SELECT dni, nombres, apellidos FROM miembros WHERE dni = %s", (dni,))
        miembro = cursor.fetchone()

        if not miembro:
            flash("Miembro no encontrado.", "danger")
            return redirect(url_for('miembros_list'))

        # Comprobar si el miembro ya tiene una cuenta de usuario
        cursor.execute("SELECT id FROM usuarios WHERE miembro_dni = %s", (dni,))
        if cursor.fetchone():
            flash("Este miembro ya tiene una cuenta de usuario asignada.", "warning")
            return redirect(url_for('miembros_list'))

        if request.method == 'POST':
            usuario = request.form['usuario']
            password = request.form['password']
            rol = request.form['rol']
            password_hash = generate_password_hash(password)

            try:
                cursor.execute("""
                    INSERT INTO usuarios (usuario, password, rol, miembro_dni) 
                    VALUES (%s, %s, %s, %s)
                """, (usuario, password_hash, rol, dni))
                mysql.connection.commit()
                flash('Cuenta de usuario creada y rol asignado exitosamente.', 'success')
                return redirect(url_for('miembros_list'))
            except Exception as e:
                flash(f'Error al crear el usuario: {str(e)}', 'danger')

    return render_template('crear_usuario_miembro.html', miembro=miembro)

# =========================================================================
# 4. Bloque de ejecución principal
# =========================================================================
if __name__ == '__main__':
 app.secret_key = 'tu_clave_secreta_aqui'
 app.run(debug=True)