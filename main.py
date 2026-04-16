import os
import pymysql
import pymysql.cursors
import pytz
from datetime import datetime
from fastapi import FastAPI, HTTPException, Query, Security, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from typing import List, Optional
from pydantic import BaseModel, field_validator # Agregamos field_validator
from starlette.status import HTTP_403_FORBIDDEN
from passlib.context import CryptContext

app = FastAPI(title="Sistema de Gestión de Ventas e Inventario")

# --- CONFIGURACIÓN DE ZONA HORARIA ---
ZONA_HORARIA = pytz.timezone('America/Mexico_City')

# Argon2 no tiene el límite de 72 caracteres, solucionando tu error de raíz.
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# 2. Funciones de ayuda (Ya no necesitan el recorte [:72])
def obtener_hash(password: str):
    return pwd_context.hash(password)

def verificar_password(password_plana, password_hasheada):
    return pwd_context.verify(password_plana, password_hasheada)
    
def obtener_ahora_str():
    """Retorna la fecha y hora actual de CDMX en formato MySQL."""
    return datetime.now(ZONA_HORARIA).strftime("%Y-%m-%d %H:%M:%S")

# --- CONFIGURACIÓN DE CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- SEGURIDAD (API KEY) ---
API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def get_api_key(header_key: str = Security(api_key_header)):
    llave_servidor = os.getenv("API_SECRET_KEY")
    if header_key == llave_servidor:
        return header_key
    raise HTTPException(
        status_code=HTTP_403_FORBIDDEN,
        detail="Acceso no autorizado"
    )

# --- CONEXIÓN A DB ---
def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", 3306)),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

# --- MODELOS CON RECORTE AUTOMÁTICO DE SEGURIDAD ---
class ItemVenta(BaseModel):
    codigo_barras: str
    cantidad: int
    total: float  

class VentaCompleta(BaseModel):
    id_venta: int 
    total: float
    productos: List[ItemVenta]
    fecha: str

class Usuario(BaseModel):
    nombre: str
    correo: str
    password: str
    rol: str

    @field_validator('password')
    @classmethod
    def recortar_password(cls, v: str) -> str:
        # Esto corta la contraseña a 72 caracteres ANTES de que llegue a la base de datos o al hash
        return v[:72]

class LoginRequest(BaseModel):
    correo: str
    password: str

    @field_validator('password')
    @classmethod
    def recortar_password(cls, v: str) -> str:
        return v[:72]

# ================================================================
# ADMINISTRACIÓN DE USUARIOS
# ================================================================

@app.post("/api/usuarios/registrar", dependencies=[Depends(get_api_key)])
def registrar_usuario(u: Usuario):
    conn = get_db_connection()
    try:
        # Aquí u.password ya viene recortada por el validador del modelo
        password_hasheada = obtener_hash(u.password)
        
        with conn.cursor() as cursor:
            query = """INSERT INTO usuarios (nombre, correo, password_hash, rol, estado) 
                       VALUES (%s, %s, %s, %s, 'Activo')"""
            cursor.execute(query, (u.nombre, u.correo, password_hasheada, u.rol))
            return {"status": "success", "message": f"Usuario {u.nombre} registrado"}
    except pymysql.err.IntegrityError:
        raise HTTPException(status_code=400, detail="El correo ya está registrado")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/api/auth/login")
def login(auth: LoginRequest):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            query = "SELECT nombre, rol, estado, password_hash FROM usuarios WHERE correo = %s"
            cursor.execute(query, (auth.correo,))
            user = cursor.fetchone()
            
            if not user:
                raise HTTPException(status_code=404, detail="Usuario no encontrado")
            
            if not verificar_password(auth.password, user['password_hash']):
                raise HTTPException(status_code=401, detail="Contraseña incorrecta")
            
            return {
                "nombre": user['nombre'],
                "rol": user['rol'],
                "estado": user['estado']
            }
    finally:
        conn.close()

# ... (El resto de tus rutas de Proveedores, Inventario y Android se mantienen iguales)

@app.get("/api/usuarios/listar", dependencies=[Depends(get_api_key)])
def listar_usuarios():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id_usuario, nombre, correo, rol, estado FROM usuarios")
            return cursor.fetchall()
    finally:
        conn.close()

@app.post("/api/usuarios/actualizar-estado", dependencies=[Depends(get_api_key)])
def actualizar_estado(correo: str, estado: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE usuarios SET estado = %s WHERE correo = %s", (estado, correo))
            return {"status": "success"}
    finally:
        conn.close()

# ================================================================
# MÓDULO ADMINISTRATIVO (STREAMLIT)
# ================================================================
@app.get("/api/admin/proveedores", dependencies=[Depends(get_api_key)])
def obtener_proveedores():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id_proveedor, nombre_empresa FROM proveedores ORDER BY nombre_empresa ASC")
            return cursor.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/api/admin/proveedores/crear", dependencies=[Depends(get_api_key)])
def crear_proveedor(nombre: str, contacto: str, tel: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "INSERT INTO proveedores (nombre_empresa, contacto_nombre, telefono) VALUES (%s, %s, %s)"
            cursor.execute(sql, (nombre, contacto, tel))
            return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/api/admin/inventario/registrar-entrada", dependencies=[Depends(get_api_key)])
def registrar_entrada(codigo: str, cantidad: int, fecha_manual: Optional[str] = Query(None)):
    conn = get_db_connection()
    try:
        # Si no mandas fecha, usamos la corregida de CDMX
        fecha_final = fecha_manual if fecha_manual else obtener_ahora_str()
        
        with conn.cursor() as cursor:
            # 1. Actualizar Stock físico
            cursor.execute("UPDATE productos SET existencias = existencias + %s WHERE codigo_barras = %s", (cantidad, codigo))

            # 2. Insertar en Historial
            cursor.execute("""
                INSERT INTO historial_stock (codigo_barras, cantidad_cambio, tipo_movimiento, fecha_movimiento) 
                VALUES (%s, %s, 'ENTRADA_PROVEEDOR', %s)
            """, (codigo, cantidad, fecha_final))
            return {"status": "success", "fecha": fecha_final}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/api/admin/inventario/crear-producto", dependencies=[Depends(get_api_key)])
def crear_producto(codigo: str, nombre: str, stock: int, minimo: int, id_prov: int, precio: float, precio_c: float, fecha_manual: Optional[str] = Query(None)): 
    conn = get_db_connection()
    try:
        fecha_final = fecha_manual if fecha_manual else obtener_ahora_str()
        with conn.cursor() as cursor:
            # 1. Insertar producto
            sql_p = """INSERT INTO productos (codigo_barras, nombre_producto, existencias, stock_minimo, id_proveedor, precio_venta, precio_compra) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql_p, (codigo, nombre, stock, minimo, id_prov, precio, precio_c))
            
            # 2. Historial inicial
            sql_h = """INSERT INTO historial_stock (codigo_barras, cantidad_cambio, tipo_movimiento, fecha_movimiento) 
                       VALUES (%s, %s, 'ENTRADA_PROVEEDOR', %s)"""
            cursor.execute(sql_h, (codigo, stock, fecha_final))
            return {"status": "success", "fecha": fecha_final}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.get("/api/admin/inventario/sugerencia-reposicion-log", dependencies=[Depends(get_api_key)])
def sugerencia_reposicion(id_proveedor: int):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        query = """
            SELECT 
                p.nombre_producto AS Producto,
                p.existencias AS Stock_Actual,
                p.stock_minimo AS Minimo,
                ABS(COALESCE((
                    SELECT SUM(h.cantidad_cambio) 
                    FROM historial_stock h 
                    WHERE h.codigo_barras = p.codigo_barras 
                    AND h.tipo_movimiento = 'VENTA' 
                    AND h.fecha_movimiento > COALESCE(
                        (SELECT MAX(fecha_movimiento) 
                         FROM historial_stock 
                         WHERE codigo_barras = p.codigo_barras 
                         AND tipo_movimiento = 'ENTRADA_PROVEEDOR'),
                        '2000-01-01'
                    )
                ), 0)) AS Vendido_Desde_Ultima_Visita
            FROM productos p
            WHERE p.id_proveedor = %s
        """
        cursor.execute(query, (id_proveedor,))
        return cursor.fetchall()
    finally:
        conn.close()

@app.get("/api/admin/dashboard/resumen", dependencies=[Depends(get_api_key)])
def resumen_dashboard():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COALESCE(SUM(total), 0) as t FROM ventas WHERE DATE(fecha_venta) = CURDATE()")
            ventas_hoy = cursor.fetchone()['t']
            
            cursor.execute("SELECT COUNT(*) as c FROM productos WHERE existencias <= stock_minimo")
            alertas = cursor.fetchone()['c']
            
            query_h = "SELECT DATE(fecha_venta) as fecha, SUM(total) as total FROM ventas GROUP BY fecha ORDER BY fecha DESC LIMIT 7"
            cursor.execute(query_h)
            return {
                "ventas_hoy": float(ventas_hoy),
                "alertas_count": alertas,
                "historico_ventas": cursor.fetchall()
            }
    finally:
        conn.close()

@app.get("/api/admin/reporte/corte-detallado", dependencies=[Depends(get_api_key)])
def reporte_corte_detallado(fecha: str = Query(...)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            query_financiero = """
                SELECT 
                    SUM(dv.cantidad * dv.precio_unitario) as ingresos_totales,
                    SUM(dv.cantidad * (dv.precio_unitario - p.precio_compra)) as ganancia_neta
                FROM detalles_ventas dv
                JOIN productos p ON dv.codigo_barras = p.codigo_barras
                JOIN ventas v ON dv.id_venta_fk = v.id_venta
                WHERE DATE(v.fecha_venta) = %s
            """
            cursor.execute(query_financiero, (fecha,))
            res = cursor.fetchone()
            
            cursor.execute("SELECT id_venta, total, fecha_venta FROM ventas WHERE DATE(fecha_venta) = %s", (fecha,))
            return {
                "ingresos": float(res['ingresos_totales'] or 0),
                "ganancia": float(res['ganancia_neta'] or 0),
                "detalles": cursor.fetchall()
            }
    finally:
        conn.close()
# Modificado para recibir el JSON de Streamlit
@app.post("/api/admin/inventario/registrar-entrada", dependencies=[Depends(get_api_key)])
def registrar_entrada(entrada: EntradaInventario):
    conn = get_db_connection()
    try:
        fecha_final = obtener_ahora_str()
        with conn.cursor() as cursor:
            # 1. Actualizar Stock físico
            cursor.execute("UPDATE productos SET existencias = existencias + %s WHERE codigo_barras = %s", (entrada.cantidad, entrada.codigo))

            # 2. Insertar en Historial
            cursor.execute("""
                INSERT INTO historial_stock (codigo_barras, cantidad_cambio, tipo_movimiento, fecha_movimiento) 
                VALUES (%s, %s, 'ENTRADA_PROVEEDOR', %s)
            """, (entrada.codigo, entrada.cantidad, fecha_final))
            return {"status": "success", "fecha": fecha_final}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

# ================================================================
# HISTORIALES Y REPORTES
# ================================================================

@app.get("/api/admin/historial/ventas", dependencies=[Depends(get_api_key)])
def historial_ventas(inicio: str, fin: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            query = """
                SELECT v.id_venta, v.fecha_venta, p.nombre_producto, dv.cantidad, dv.precio_unitario, (dv.cantidad * dv.precio_unitario) as total
                FROM ventas v
                JOIN detalles_ventas dv ON v.id_venta = dv.id_venta_fk
                JOIN productos p ON dv.codigo_barras = p.codigo_barras
                WHERE DATE(v.fecha_venta) BETWEEN %s AND %s
                ORDER BY v.fecha_venta DESC
            """
            cursor.execute(query, (inicio, fin))
            return cursor.fetchall()
    finally:
        conn.close()

@app.get("/api/admin/historial/compras", dependencies=[Depends(get_api_key)])
def historial_compras(inicio: str, fin: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            query = """
                SELECT h.fecha_movimiento, p.nombre_producto, h.cantidad_cambio as cantidad_ingresada, p.precio_compra, (h.cantidad_cambio * p.precio_compra) as inversion_estimada
                FROM historial_stock h
                JOIN productos p ON h.codigo_barras = p.codigo_barras
                WHERE h.tipo_movimiento = 'ENTRADA_PROVEEDOR' 
                AND DATE(h.fecha_movimiento) BETWEEN %s AND %s
                ORDER BY h.fecha_movimiento DESC
            """
            cursor.execute(query, (inicio, fin))
            return cursor.fetchall()
    finally:
        conn.close()

@app.get("/api/admin/proveedores", dependencies=[Depends(get_api_key)])
def obtener_proveedores():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id_proveedor, nombre_empresa FROM proveedores ORDER BY nombre_empresa ASC")
            return cursor.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.get("/api/admin/dashboard/resumen", dependencies=[Depends(get_api_key)])
def resumen_dashboard():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COALESCE(SUM(total), 0) as t FROM ventas WHERE DATE(fecha_venta) = CURDATE()")
            ventas_hoy = cursor.fetchone()['t']
            
            cursor.execute("SELECT COUNT(*) as c FROM productos WHERE existencias <= stock_minimo")
            alertas = cursor.fetchone()['c']
            
            query_h = "SELECT DATE(fecha_venta) as fecha, SUM(total) as total FROM ventas GROUP BY fecha ORDER BY fecha DESC LIMIT 7"
            cursor.execute(query_h)
            return {
                "ventas_hoy": float(ventas_hoy),
                "alertas_count": alertas,
                "historico_ventas": cursor.fetchall()
            }
    finally:
        conn.close()

@app.get("/api/admin/reporte/corte-detallado", dependencies=[Depends(get_api_key)])
def reporte_corte_detallado(fecha: str = Query(...)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            query_financiero = """
                SELECT 
                    SUM(dv.cantidad * dv.precio_unitario) as ingresos_totales,
                    SUM(dv.cantidad * (dv.precio_unitario - p.precio_compra)) as ganancia_neta
                FROM detalles_ventas dv
                JOIN productos p ON dv.codigo_barras = p.codigo_barras
                JOIN ventas v ON dv.id_venta_fk = v.id_venta
                WHERE DATE(v.fecha_venta) = %s
            """
            cursor.execute(query_financiero, (fecha,))
            res = cursor.fetchone()
            
            cursor.execute("SELECT id_venta, total, fecha_venta FROM ventas WHERE DATE(fecha_venta) = %s", (fecha,))
            return {
                "ingresos": float(res['ingresos_totales'] or 0),
                "ganancia": float(res['ganancia_neta'] or 0),
                "detalles": cursor.fetchall()
            }
    finally:
        conn.close()


# ================================================================
# MÓDULO ANDROID (SINCRONIZACIÓN RESILIENTE)
# ================================================================

@app.get("/listar_productos", dependencies=[Depends(get_api_key)])
def listar_productos():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT codigo_barras, nombre_producto, precio_compra, precio_venta, existencias FROM productos")
            return cursor.fetchall()
    finally:
        conn.close()

@app.post("/vender_detalle", dependencies=[Depends(get_api_key)])
async def vender_detalle(venta: VentaCompleta):
    conexion = get_db_connection()
    try:
        with conexion.cursor() as cursor:
            try:
                # 1. AGRUPAR PRODUCTOS (Evita duplicados en una sola transacción)
                productos_agrupados = {}
                for p in venta.productos:
                    if p.codigo_barras in productos_agrupados:
                        productos_agrupados[p.codigo_barras]['cantidad'] += p.cantidad
                    else:
                        productos_agrupados[p.codigo_barras] = {'cantidad': p.cantidad, 'precio': p.total}

                # 2. INSERTAR CABECERA (Usa la fecha que manda el ZTE)
                sql_cabecera = "INSERT INTO ventas (total, id_android_local, fecha_venta) VALUES (%s, %s, %s)"
                cursor.execute(sql_cabecera, (float(venta.total), int(venta.id_venta), str(venta.fecha)))
                id_generado = conexion.insert_id()

                # 3. PROCESAR PRODUCTOS
                sql_detalle = "INSERT INTO detalles_ventas (id_venta_fk, codigo_barras, cantidad, precio_unitario) VALUES (%s, %s, %s, %s)"
                sql_update_stock = "UPDATE productos SET existencias = existencias - %s WHERE codigo_barras = %s"
                sql_historial = "INSERT INTO historial_stock (codigo_barras, cantidad_cambio, tipo_movimiento, fecha_movimiento) VALUES (%s, %s, 'VENTA', %s)"

                for codigo, datos in productos_agrupados.items():
                    cursor.execute(sql_detalle, (id_generado, codigo, datos['cantidad'], datos['precio']))
                    cursor.execute(sql_update_stock, (datos['cantidad'], codigo))
                    cursor.execute(sql_historial, (codigo, -datos['cantidad'], venta.fecha))

                conexion.commit()
                return {"status": "ok", "id_nube": id_generado}
            except pymysql.err.IntegrityError:
                return {"status": "success", "message": "Ya sincronizada", "id_nube": -1}
    except Exception as e:
        if conexion: conexion.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conexion.close()

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
