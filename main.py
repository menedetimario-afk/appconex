import os
import pymysql
import pymysql.cursors
import pytz
from datetime import datetime
from fastapi import FastAPI, HTTPException, Query, Security, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from typing import List, Optional
from pydantic import BaseModel, field_validator
from starlette.status import HTTP_403_FORBIDDEN
from passlib.context import CryptContext

app = FastAPI(title="Sistema de Gestión de Ventas e Inventario")

# --- CONFIGURACIÓN DE ZONA HORARIA ---
ZONA_HORARIA = pytz.timezone('America/Mexico_City')

# Argon2 para seguridad de contraseñas
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# --- FUNCIONES DE AYUDA ---
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
    raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Acceso no autorizado")

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

# --- MODELOS ---
class EntradaInventario(BaseModel):
    codigo: str
    cantidad: int

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
        return v[:72]

class LoginRequest(BaseModel):
    correo: str
    password: str
    @field_validator('password')
    @classmethod
    def recortar_password(cls, v: str) -> str:
        return v[:72]

class ProveedorNuevo(BaseModel):
    nombre: str
    contacto: str
    tel: str

class ProductoNuevo(BaseModel):
    codigo: str
    nombre: str
    stock: int
    minimo: int
    id_prov: int
    precio: float
    precio_c: float
# ================================================================
# ADMINISTRACIÓN DE USUARIOS Y AUTH
# ================================================================

@app.post("/api/auth/login")
def login(auth: LoginRequest):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT nombre, rol, estado, password_hash FROM usuarios WHERE correo = %s", (auth.correo,))
            user = cursor.fetchone()
            if not user or not verificar_password(auth.password, user['password_hash']):
                raise HTTPException(status_code=401, detail="Credenciales incorrectas")
            return user
    finally:
        conn.close()

@app.post("/api/usuarios/registrar", dependencies=[Depends(get_api_key)])
def registrar_usuario(u: Usuario):
    conn = get_db_connection()
    try:
        password_hasheada = obtener_hash(u.password)
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO usuarios (nombre, correo, password_hash, rol, estado) VALUES (%s, %s, %s, %s, 'Activo')",
                           (u.nombre, u.correo, password_hasheada, u.rol))
            return {"status": "success"}
    finally:
        conn.close()

@app.get("/api/usuarios/listar", dependencies=[Depends(get_api_key)])
def listar_usuarios():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id_usuario, nombre, correo, rol, estado FROM usuarios")
            return cursor.fetchall()
    finally:
        conn.close()

@app.put("/api/usuarios/desactivar/{id_usuario}", dependencies=[Depends(get_api_key)])
def desactivar_usuario(id_usuario: int):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE usuarios SET estado = 'Inactivo' WHERE id_usuario = %s", (id_usuario,))
            return {"status": "success", "message": "Usuario desactivado"}
    finally:
        conn.close()

@app.delete("/api/usuarios/eliminar/{id_usuario}", dependencies=[Depends(get_api_key)])
def eliminar_usuario(id_usuario: int):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM usuarios WHERE id_usuario = %s", (id_usuario,))
            return {"status": "success", "message": "Usuario eliminado"}
    finally:
        conn.close()

# ================================================================
# MÓDULO ADMINISTRATIVO (INVENTARIO Y PROVEEDORES)
# ================================================================

@app.get("/api/admin/proveedores", dependencies=[Depends(get_api_key)])
def obtener_proveedores():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Aseguramos que exista la columna nombre_empresa
            cursor.execute("SELECT id_proveedor, nombre_empresa FROM proveedores ORDER BY nombre_empresa ASC")
            return cursor.fetchall()
    finally:
        conn.close()

@app.post("/api/admin/proveedores/crear", dependencies=[Depends(get_api_key)])
def crear_proveedor(p: ProveedorNuevo): # <--- Ahora recibe un objeto
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO proveedores (nombre_empresa, contacto_nombre, telefono) VALUES (%s, %s, %s)", 
                (p.nombre, p.contacto, p.tel)
            )
            return {"status": "success"}
    finally:
        conn.close()

@app.post("/api/admin/inventario/registrar-entrada", dependencies=[Depends(get_api_key)])
def registrar_entrada(entrada: EntradaInventario):
    conn = get_db_connection()
    try:
        fecha = obtener_ahora_str()
        with conn.cursor() as cursor:
            # 1. Actualizar existencias
            cursor.execute("UPDATE productos SET existencias = existencias + %s WHERE codigo_barras = %s", 
                           (entrada.cantidad, entrada.codigo))
            # 2. Registrar en historial
            cursor.execute("""INSERT INTO historial_stock (codigo_barras, cantidad_cambio, tipo_movimiento, fecha_movimiento) 
                           VALUES (%s, %s, 'ENTRADA_PROVEEDOR', %s)""",
                           (entrada.codigo, entrada.cantidad, fecha))
            return {"status": "success", "message": "Inventario actualizado"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/api/admin/inventario/crear-producto", dependencies=[Depends(get_api_key)])
def crear_producto(p: ProductoNuevo): # <--- Ahora recibe el objeto completo
    conn = get_db_connection()
    try:
        fecha_final = obtener_ahora_str()
        with conn.cursor() as cursor:
            # Usamos p.propiedad para acceder a los datos del JSON
            cursor.execute("""
                INSERT INTO productos 
                (codigo_barras, nombre_producto, existencias, stock_minimo, id_proveedor, precio_venta, precio_compra) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (p.codigo, p.nombre, p.stock, p.minimo, p.id_prov, p.precio, p.precio_c))
            
            cursor.execute("""
                INSERT INTO historial_stock 
                (codigo_barras, cantidad_cambio, tipo_movimiento, fecha_movimiento) 
                VALUES (%s, %s, 'ENTRADA_PROVEEDOR', %s)
            """, (p.codigo, p.stock, fecha_final))
            
            return {"status": "success"}
    except Exception as e:
        print(f"Error al crear producto: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

# ================================================================
# CORTE DE CAJA
# ================================================================
@app.get("/api/admin/reporte/corte-detallado", dependencies=[Depends(get_api_key)])
def reporte_corte_detallado(fecha: str = Query(...)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Cálculos financieros
            cursor.execute("""
                SELECT 
                    SUM(dv.cantidad * dv.precio_unitario) as ingresos,
                    SUM(dv.cantidad * (dv.precio_unitario - p.precio_compra)) as ganancia
                FROM detalles_ventas dv
                JOIN productos p ON dv.codigo_barras = p.codigo_barras
                JOIN ventas v ON dv.id_venta_fk = v.id_venta
                WHERE DATE(v.fecha_venta) = %s
            """, (fecha,))
            res = cursor.fetchone()
            
            # Listado de tickets
            cursor.execute("SELECT id_venta, total, fecha_venta FROM ventas WHERE DATE(fecha_venta) = %s", (fecha,))
            detalles = cursor.fetchall()
            
            # Formateo seguro de nulos
            ingresos = float(res['ingresos']) if res and res['ingresos'] else 0.0
            ganancia = float(res['ganancia']) if res and res['ganancia'] else 0.0
            
            return {
                "ingresos": ingresos,
                "ganancia": ganancia,
                "detalles": detalles
            }
    finally:
        conn.close()
# ================================================================
# HISTORIALES Y DASHBOARD (RECUPERADOS)
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

@app.get("/api/admin/dashboard/resumen", dependencies=[Depends(get_api_key)])
def resumen_dashboard():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COALESCE(SUM(total), 0) as t FROM ventas WHERE DATE(fecha_venta) = CURDATE()")
            hoy = cursor.fetchone()['t']
            cursor.execute("SELECT COUNT(*) as c FROM productos WHERE existencias <= stock_minimo")
            alertas = cursor.fetchone()['c']
            return {"ventas_hoy": float(hoy), "alertas_count": alertas}
    finally:
        conn.close()

@app.get("/api/admin/dashboard/grafico-ventas", dependencies=[Depends(get_api_key)])
def datos_grafico_ventas():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Obtenemos las ventas sumadas por día de la última semana
            query = """
                SELECT DATE(fecha_venta) as fecha, SUM(total) as total_dia
                FROM ventas
                WHERE fecha_venta >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
                GROUP BY DATE(fecha_venta)
                ORDER BY fecha ASC
            """
            cursor.execute(query)
            return cursor.fetchall()
    finally:
        conn.close()

# ================================================================
# MÓDULO 
# ================================================================

@app.get("/listar_productos", dependencies=[Depends(get_api_key)])
def listar_productos():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # AGREGAMOS precio_venta a la consulta
            cursor.execute("SELECT codigo_barras, nombre_producto, precio_venta, precio_compra, existencias FROM productos")
            return cursor.fetchall()
    finally:
        conn.close()

@app.post("/vender_detalle", dependencies=[Depends(get_api_key)])
async def vender_detalle(venta: VentaCompleta):
    conexion = get_db_connection()
    try:
        with conexion.cursor() as cursor:
            try:
                cursor.execute("INSERT INTO ventas (total, id_android_local, fecha_venta) VALUES (%s, %s, %s)", 
                               (float(venta.total), int(venta.id_venta), str(venta.fecha)))
                id_generado = conexion.insert_id()
                for p in venta.productos:
                    cursor.execute("INSERT INTO detalles_ventas (id_venta_fk, codigo_barras, cantidad, precio_unitario) VALUES (%s, %s, %s, %s)",
                                   (id_generado, p.codigo_barras, p.cantidad, p.total))
                    cursor.execute("UPDATE productos SET existencias = existencias - %s WHERE codigo_barras = %s", (p.cantidad, p.codigo_barras))
                    cursor.execute("INSERT INTO historial_stock (codigo_barras, cantidad_cambio, tipo_movimiento, fecha_movimiento) VALUES (%s, %s, 'VENTA', %s)",
                                   (p.codigo_barras, -p.cantidad, venta.fecha))
                conexion.commit()
                return {"status": "ok", "id_nube": id_generado}
            except pymysql.err.IntegrityError:
                return {"status": "success", "message": "Ya sincronizada", "id_nube": -1}
    except Exception as e:
        if conexion: conexion.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conexion.close()

# ================================================================
# MÓDULO DE VENTAS (NUEVO)
# ================================================================

@app.post("/api/ventas/registrar", dependencies=[Depends(get_api_key)])
def registrar_venta_completa(venta: VentaCompleta):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            fecha_actual = obtener_ahora_str()
            # Quitamos el id_android_local si no es necesario o lo ponemos como opcional
            cursor.execute(
                "INSERT INTO ventas (total, fecha_venta) VALUES (%s, %s)",
                (venta.total, fecha_actual)
            )
            id_venta = conn.insert_id()

            for item in venta.productos:
                cursor.execute(
                    "INSERT INTO detalles_ventas (id_venta_fk, codigo_barras, cantidad, precio_unitario) VALUES (%s, %s, %s, %s)",
                    (id_venta, item.codigo_barras, item.cantidad, item.total)
                )
                cursor.execute(
                    "UPDATE productos SET existencias = existencias - %s WHERE codigo_barras = %s",
                    (item.cantidad, item.codigo_barras)
                )
                cursor.execute(
                    "INSERT INTO historial_stock (codigo_barras, cantidad_cambio, tipo_movimiento, fecha_movimiento) VALUES (%s, %s, 'VENTA', %s)",
                    (item.codigo_barras, -item.cantidad, fecha_actual)
                )
            
            conn.commit()
            return {"status": "success", "id_venta": id_venta}
    except Exception as e:
        conn.rollback()
        # Esto te ayudará a ver el error real en los logs de la API
        print(f"Error en venta: {str(e)}") 
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
