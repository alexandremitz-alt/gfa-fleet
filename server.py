from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import Response
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import jwt
import httpx
import base64
import aiomysql

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MySQL connection settings
MYSQL_CONFIG = {
    'host': os.environ.get('MYSQL_HOST', 'br562.hostgator.com.br'),
    'port': int(os.environ.get('MYSQL_PORT', 3306)),
    'user': os.environ.get('MYSQL_USER', 'gfane159_fleetuser'),
    'password': os.environ.get('MYSQL_PASSWORD', '147963As$#'),
    'db': os.environ.get('MYSQL_DATABASE', 'gfane159_fleet'),
    'charset': 'utf8mb4',
    'autocommit': True
}

# Connection pool
pool = None

async def get_pool():
    global pool
    if pool is None:
        pool = await aiomysql.create_pool(**MYSQL_CONFIG, minsize=1, maxsize=10)
    return pool

async def execute_query(query: str, params: tuple = None, fetch: str = None):
    """Execute a query and optionally fetch results"""
    p = await get_pool()
    async with p.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(query, params)
            if fetch == 'one':
                return await cur.fetchone()
            elif fetch == 'all':
                return await cur.fetchall()
            return cur.lastrowid

# JWT Config
JWT_SECRET = os.environ.get('JWT_SECRET', 'gfa-fleet-secret-key-2024')
JWT_ALGORITHM = "HS256"

# External Auth API
EXTERNAL_AUTH_API = "https://web-production-83c44.up.railway.app/api"
SISTEMA_TAG = "veiculos"

# Create the main app
app = FastAPI(title="GFA Fleet Control API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

security = HTTPBearer()

# ==================== MODELS ====================

class UserLogin(BaseModel):
    email: EmailStr
    senha: str

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: str

class VehicleCreate(BaseModel):
    plate: str
    model: str
    year: int
    current_km: int

class VehicleUpdate(BaseModel):
    plate: Optional[str] = None
    model: Optional[str] = None
    year: Optional[int] = None
    current_km: Optional[int] = None

class VehicleResponse(BaseModel):
    id: str
    plate: str
    model: str
    year: int
    current_km: int
    pdf_document: Optional[str] = None
    next_oil_change_km: Optional[int] = None
    last_balance_km: Optional[int] = None
    last_alignment_km: Optional[int] = None
    oil_status: str = "ok"
    tire_balance_status: str = "ok"
    tire_alignment_status: str = "ok"
    created_at: str

class OilChangeCreate(BaseModel):
    vehicle_id: str
    current_km: int
    next_change_km: int
    notes: Optional[str] = None

class OilChangeResponse(BaseModel):
    id: str
    vehicle_id: str
    current_km: int
    next_change_km: int
    notes: Optional[str] = None
    created_at: str
    created_by: str

class TireMaintenanceCreate(BaseModel):
    vehicle_id: str
    current_km: int
    notes: Optional[str] = None

class TireMaintenanceResponse(BaseModel):
    id: str
    vehicle_id: str
    current_km: int
    notes: Optional[str] = None
    created_at: str
    created_by: str

class DashboardStats(BaseModel):
    total_vehicles: int
    vehicles_ok: int
    vehicles_warning: int
    vehicles_needing_attention: List[VehicleResponse]

class DailyCheckinCreate(BaseModel):
    vehicle_id: str
    current_km: int
    oil_checked: bool = False
    water_checked: bool = False
    general_condition: str
    anomaly_description: Optional[str] = None

class DailyCheckinResponse(BaseModel):
    id: str
    vehicle_id: str
    current_km: int
    oil_checked: bool
    water_checked: bool
    general_condition: str
    anomaly_description: Optional[str] = None
    anomaly_id: Optional[str] = None
    created_at: str
    created_by: str
    created_by_name: Optional[str] = None

class AnomalyResponse(BaseModel):
    id: str
    vehicle_id: str
    checkin_id: str
    description: str
    status: str
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_notes: Optional[str] = None
    created_at: str
    created_by: str
    created_by_name: Optional[str] = None

class AnomalyResolve(BaseModel):
    notes: Optional[str] = None

class FuelRefuelingCreate(BaseModel):
    vehicle_id: str
    current_km: int
    liters: float
    value: float
    fuel_type: str

class FuelRefuelingResponse(BaseModel):
    id: str
    vehicle_id: str
    current_km: int
    liters: float
    value: float
    fuel_type: str
    price_per_liter: float
    created_at: str
    created_by: str
    created_by_name: Optional[str] = None

# ==================== AUTH HELPERS ====================

def create_token(user_id: str, email: str, role: str, name: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "role": role,
        "name": name,
        "exp": datetime.now(timezone.utc).timestamp() + 86400 * 7
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def format_datetime(dt):
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/login", response_model=dict)
async def login(credentials: UserLogin):
    try:
        async with httpx.AsyncClient() as http_client:
            response = await http_client.post(
                f"{EXTERNAL_AUTH_API}/auth/validate?sistema={SISTEMA_TAG}",
                json={"email": credentials.email, "senha": credentials.senha},
                headers={"Content-Type": "application/json"},
                timeout=10.0
            )
            
            if response.status_code == 401:
                error_data = response.json()
                raise HTTPException(status_code=401, detail=error_data.get("detail", "Credenciais inválidas"))
            
            if response.status_code == 403:
                raise HTTPException(status_code=403, detail="Usuário sem acesso ao sistema de veículos")
            
            if response.status_code != 200:
                raise HTTPException(status_code=401, detail="Erro na autenticação")
            
            data = response.json()
            
            if not data.get("valid"):
                raise HTTPException(status_code=401, detail="Credenciais inválidas")
            
            ext_user = data.get("user", {})
            user_id = ext_user.get("id")
            user_name = ext_user.get("nome", "Usuário")
            user_email = ext_user.get("email")
            user_cargo = ext_user.get("cargo", "").lower()
            
            role = "admin" if user_cargo == "administrador" else "user"
            token = create_token(user_id, user_email, role, user_name)
            
            return {
                "token": token,
                "user": {
                    "id": user_id,
                    "name": user_name,
                    "email": user_email,
                    "role": role
                }
            }
            
    except httpx.RequestError as e:
        logging.error(f"Auth API request error: {e}")
        raise HTTPException(status_code=503, detail="Serviço de autenticação indisponível")

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user.get("user_id"),
        "name": current_user.get("name", "Usuário"),
        "email": current_user.get("email"),
        "role": current_user.get("role")
    }

# ==================== VEHICLE HELPERS ====================

def calculate_vehicle_status(vehicle: dict) -> dict:
    current_km = vehicle.get("current_km", 0) or 0
    next_oil = vehicle.get("next_oil_change_km")
    last_balance = vehicle.get("last_balance_km")
    last_alignment = vehicle.get("last_alignment_km")
    
    oil_status = "ok"
    if next_oil and (next_oil - current_km) < 1000:
        oil_status = "warning"
    
    tire_status = "ok"
    if last_balance and (current_km - last_balance) > 5000:
        tire_status = "warning"
    if last_alignment and (current_km - last_alignment) > 5000:
        tire_status = "warning"
    
    vehicle["oil_status"] = oil_status
    vehicle["tire_status"] = tire_status
    vehicle["tire_balance_status"] = tire_status
    vehicle["tire_alignment_status"] = tire_status
    vehicle["created_at"] = format_datetime(vehicle.get("created_at"))
    
    return vehicle

# ==================== VEHICLE ROUTES ====================

@api_router.get("/vehicles", response_model=List[VehicleResponse])
async def get_vehicles(current_user: dict = Depends(get_current_user)):
    vehicles = await execute_query("SELECT * FROM vehicles ORDER BY plate", fetch='all')
    return [calculate_vehicle_status(dict(v)) for v in vehicles]

@api_router.get("/vehicles/{vehicle_id}", response_model=VehicleResponse)
async def get_vehicle(vehicle_id: str, current_user: dict = Depends(get_current_user)):
    vehicle = await execute_query("SELECT * FROM vehicles WHERE id = %s", (vehicle_id,), fetch='one')
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    return calculate_vehicle_status(dict(vehicle))

@api_router.post("/vehicles", response_model=VehicleResponse, status_code=201)
async def create_vehicle(vehicle: VehicleCreate, current_user: dict = Depends(get_current_user)):
    existing = await execute_query("SELECT id FROM vehicles WHERE plate = %s", (vehicle.plate.upper(),), fetch='one')
    if existing:
        raise HTTPException(status_code=400, detail="Vehicle with this plate already exists")
    
    vehicle_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    await execute_query(
        """INSERT INTO vehicles (id, plate, model, year, current_km, created_at) 
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (vehicle_id, vehicle.plate.upper(), vehicle.model, vehicle.year, vehicle.current_km, now)
    )
    
    vehicle_doc = {
        "id": vehicle_id,
        "plate": vehicle.plate.upper(),
        "model": vehicle.model,
        "year": vehicle.year,
        "current_km": vehicle.current_km,
        "pdf_document": None,
        "next_oil_change_km": None,
        "last_balance_km": None,
        "last_alignment_km": None,
        "created_at": now
    }
    return calculate_vehicle_status(vehicle_doc)

@api_router.put("/vehicles/{vehicle_id}", response_model=VehicleResponse)
async def update_vehicle(vehicle_id: str, vehicle_update: VehicleUpdate, admin: dict = Depends(require_admin)):
    vehicle = await execute_query("SELECT * FROM vehicles WHERE id = %s", (vehicle_id,), fetch='one')
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    
    update_fields = []
    update_values = []
    
    if vehicle_update.plate is not None:
        update_fields.append("plate = %s")
        update_values.append(vehicle_update.plate.upper())
    if vehicle_update.model is not None:
        update_fields.append("model = %s")
        update_values.append(vehicle_update.model)
    if vehicle_update.year is not None:
        update_fields.append("year = %s")
        update_values.append(vehicle_update.year)
    if vehicle_update.current_km is not None:
        update_fields.append("current_km = %s")
        update_values.append(vehicle_update.current_km)
    
    if not update_fields:
        raise HTTPException(status_code=400, detail="No data to update")
    
    update_values.append(vehicle_id)
    await execute_query(
        f"UPDATE vehicles SET {', '.join(update_fields)} WHERE id = %s",
        tuple(update_values)
    )
    
    updated = await execute_query("SELECT * FROM vehicles WHERE id = %s", (vehicle_id,), fetch='one')
    return calculate_vehicle_status(dict(updated))

@api_router.delete("/vehicles/{vehicle_id}")
async def delete_vehicle(vehicle_id: str, admin: dict = Depends(require_admin)):
    result = await execute_query("SELECT id FROM vehicles WHERE id = %s", (vehicle_id,), fetch='one')
    if not result:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    await execute_query("DELETE FROM vehicles WHERE id = %s", (vehicle_id,))
    return {"message": "Vehicle deleted successfully"}

@api_router.post("/vehicles/{vehicle_id}/upload-pdf")
async def upload_vehicle_pdf(vehicle_id: str, file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")
    
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds 5MB limit")
    
    pdf_base64 = base64.b64encode(content).decode('utf-8')
    
    result = await execute_query("SELECT id FROM vehicles WHERE id = %s", (vehicle_id,), fetch='one')
    if not result:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    
    await execute_query("UPDATE vehicles SET pdf_document = %s WHERE id = %s", (pdf_base64, vehicle_id))
    return {"message": "PDF uploaded successfully"}

@api_router.get("/vehicles/{vehicle_id}/pdf")
async def get_vehicle_pdf(vehicle_id: str, current_user: dict = Depends(get_current_user)):
    vehicle = await execute_query("SELECT pdf_document FROM vehicles WHERE id = %s", (vehicle_id,), fetch='one')
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    if not vehicle.get("pdf_document"):
        raise HTTPException(status_code=404, detail="No PDF document found")
    
    pdf_bytes = base64.b64decode(vehicle["pdf_document"])
    return Response(content=pdf_bytes, media_type="application/pdf")

# ==================== OIL CHANGE ROUTES ====================

@api_router.get("/oil-changes", response_model=List[OilChangeResponse])
async def get_oil_changes(vehicle_id: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    if vehicle_id:
        oil_changes = await execute_query(
            "SELECT * FROM oil_changes WHERE vehicle_id = %s ORDER BY created_at DESC",
            (vehicle_id,), fetch='all'
        )
    else:
        oil_changes = await execute_query("SELECT * FROM oil_changes ORDER BY created_at DESC", fetch='all')
    
    return [{**dict(o), "created_at": format_datetime(o["created_at"])} for o in oil_changes]

@api_router.post("/oil-changes", response_model=OilChangeResponse, status_code=201)
async def create_oil_change(oil_change: OilChangeCreate, current_user: dict = Depends(get_current_user)):
    vehicle = await execute_query("SELECT id FROM vehicles WHERE id = %s", (oil_change.vehicle_id,), fetch='one')
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    
    oil_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    await execute_query(
        """INSERT INTO oil_changes (id, vehicle_id, current_km, next_change_km, notes, created_at, created_by)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (oil_id, oil_change.vehicle_id, oil_change.current_km, oil_change.next_change_km, 
         oil_change.notes, now, current_user["user_id"])
    )
    
    await execute_query(
        "UPDATE vehicles SET current_km = %s, next_oil_change_km = %s WHERE id = %s",
        (oil_change.current_km, oil_change.next_change_km, oil_change.vehicle_id)
    )
    
    return {
        "id": oil_id,
        "vehicle_id": oil_change.vehicle_id,
        "current_km": oil_change.current_km,
        "next_change_km": oil_change.next_change_km,
        "notes": oil_change.notes,
        "created_at": now.isoformat(),
        "created_by": current_user["user_id"]
    }

@api_router.delete("/oil-changes/{oil_id}")
async def delete_oil_change(oil_id: str, admin: dict = Depends(require_admin)):
    result = await execute_query("SELECT id FROM oil_changes WHERE id = %s", (oil_id,), fetch='one')
    if not result:
        raise HTTPException(status_code=404, detail="Oil change record not found")
    await execute_query("DELETE FROM oil_changes WHERE id = %s", (oil_id,))
    return {"message": "Oil change record deleted successfully"}

# ==================== TIRE MAINTENANCE ROUTES ====================

@api_router.get("/tire-maintenances", response_model=List[TireMaintenanceResponse])
async def get_tire_maintenances(vehicle_id: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    if vehicle_id:
        maintenances = await execute_query(
            "SELECT * FROM tire_maintenances WHERE vehicle_id = %s ORDER BY created_at DESC",
            (vehicle_id,), fetch='all'
        )
    else:
        maintenances = await execute_query("SELECT * FROM tire_maintenances ORDER BY created_at DESC", fetch='all')
    
    return [{**dict(m), "created_at": format_datetime(m["created_at"])} for m in maintenances]

@api_router.post("/tire-maintenances", response_model=TireMaintenanceResponse, status_code=201)
async def create_tire_maintenance(maintenance: TireMaintenanceCreate, current_user: dict = Depends(get_current_user)):
    vehicle = await execute_query("SELECT id FROM vehicles WHERE id = %s", (maintenance.vehicle_id,), fetch='one')
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    
    maintenance_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    await execute_query(
        """INSERT INTO tire_maintenances (id, vehicle_id, current_km, notes, created_at, created_by)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (maintenance_id, maintenance.vehicle_id, maintenance.current_km, maintenance.notes, now, current_user["user_id"])
    )
    
    await execute_query(
        "UPDATE vehicles SET current_km = %s, last_balance_km = %s, last_alignment_km = %s WHERE id = %s",
        (maintenance.current_km, maintenance.current_km, maintenance.current_km, maintenance.vehicle_id)
    )
    
    return {
        "id": maintenance_id,
        "vehicle_id": maintenance.vehicle_id,
        "current_km": maintenance.current_km,
        "notes": maintenance.notes,
        "created_at": now.isoformat(),
        "created_by": current_user["user_id"]
    }

@api_router.delete("/tire-maintenances/{maintenance_id}")
async def delete_tire_maintenance(maintenance_id: str, admin: dict = Depends(require_admin)):
    result = await execute_query("SELECT id FROM tire_maintenances WHERE id = %s", (maintenance_id,), fetch='one')
    if not result:
        raise HTTPException(status_code=404, detail="Tire maintenance record not found")
    await execute_query("DELETE FROM tire_maintenances WHERE id = %s", (maintenance_id,))
    return {"message": "Tire maintenance record deleted successfully"}

# ==================== DAILY CHECK-IN ROUTES ====================

@api_router.get("/daily-checkins", response_model=List[DailyCheckinResponse])
async def get_daily_checkins(vehicle_id: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    if vehicle_id:
        checkins = await execute_query(
            "SELECT * FROM daily_checkins WHERE vehicle_id = %s ORDER BY created_at DESC",
            (vehicle_id,), fetch='all'
        )
    else:
        checkins = await execute_query("SELECT * FROM daily_checkins ORDER BY created_at DESC", fetch='all')
    
    return [{**dict(c), "created_at": format_datetime(c["created_at"]), 
             "oil_checked": bool(c["oil_checked"]), "water_checked": bool(c["water_checked"])} for c in checkins]

@api_router.get("/daily-checkins/today/{vehicle_id}")
async def get_today_checkin(vehicle_id: str, current_user: dict = Depends(get_current_user)):
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    checkin = await execute_query(
        "SELECT * FROM daily_checkins WHERE vehicle_id = %s AND created_at >= %s ORDER BY created_at DESC LIMIT 1",
        (vehicle_id, today_start), fetch='one'
    )
    if checkin:
        return {**dict(checkin), "created_at": format_datetime(checkin["created_at"]),
                "oil_checked": bool(checkin["oil_checked"]), "water_checked": bool(checkin["water_checked"])}
    return None

@api_router.post("/daily-checkins", response_model=DailyCheckinResponse, status_code=201)
async def create_daily_checkin(checkin: DailyCheckinCreate, current_user: dict = Depends(get_current_user)):
    vehicle = await execute_query("SELECT * FROM vehicles WHERE id = %s", (checkin.vehicle_id,), fetch='one')
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    
    vehicle_current_km = vehicle.get("current_km", 0) or 0
    
    if checkin.current_km < vehicle_current_km:
        raise HTTPException(
            status_code=400, 
            detail=f"Km informado ({checkin.current_km:,}) não pode ser menor que o km atual do veículo ({vehicle_current_km:,}). Apenas administradores podem corrigir a quilometragem na edição do veículo."
        )
    
    checkin_id = str(uuid.uuid4())
    anomaly_id = None
    now = datetime.now(timezone.utc)
    
    if checkin.anomaly_description and checkin.anomaly_description.strip():
        anomaly_id = str(uuid.uuid4())
        await execute_query(
            """INSERT INTO anomalies (id, vehicle_id, checkin_id, description, status, created_at, created_by, created_by_name)
               VALUES (%s, %s, %s, %s, 'pending', %s, %s, %s)""",
            (anomaly_id, checkin.vehicle_id, checkin_id, checkin.anomaly_description.strip(),
             now, current_user["user_id"], current_user.get("name", "Usuário"))
        )
    
    await execute_query(
        """INSERT INTO daily_checkins (id, vehicle_id, current_km, oil_checked, water_checked, 
           general_condition, anomaly_description, anomaly_id, created_at, created_by, created_by_name)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (checkin_id, checkin.vehicle_id, checkin.current_km, checkin.oil_checked, checkin.water_checked,
         checkin.general_condition, checkin.anomaly_description, anomaly_id, now,
         current_user["user_id"], current_user.get("name", "Usuário"))
    )
    
    await execute_query("UPDATE vehicles SET current_km = %s WHERE id = %s", (checkin.current_km, checkin.vehicle_id))
    
    return {
        "id": checkin_id,
        "vehicle_id": checkin.vehicle_id,
        "current_km": checkin.current_km,
        "oil_checked": checkin.oil_checked,
        "water_checked": checkin.water_checked,
        "general_condition": checkin.general_condition,
        "anomaly_description": checkin.anomaly_description,
        "anomaly_id": anomaly_id,
        "created_at": now.isoformat(),
        "created_by": current_user["user_id"],
        "created_by_name": current_user.get("name", "Usuário")
    }

@api_router.delete("/daily-checkins/{checkin_id}")
async def delete_daily_checkin(checkin_id: str, admin: dict = Depends(require_admin)):
    checkin = await execute_query("SELECT * FROM daily_checkins WHERE id = %s", (checkin_id,), fetch='one')
    if not checkin:
        raise HTTPException(status_code=404, detail="Check-in not found")
    
    if checkin.get("anomaly_id"):
        await execute_query("DELETE FROM anomalies WHERE id = %s", (checkin["anomaly_id"],))
    
    await execute_query("DELETE FROM daily_checkins WHERE id = %s", (checkin_id,))
    return {"message": "Check-in deleted successfully"}

# ==================== ANOMALY ROUTES ====================

@api_router.get("/anomalies", response_model=List[AnomalyResponse])
async def get_anomalies(vehicle_id: Optional[str] = None, status: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    query = "SELECT * FROM anomalies WHERE 1=1"
    params = []
    
    if vehicle_id:
        query += " AND vehicle_id = %s"
        params.append(vehicle_id)
    if status:
        query += " AND status = %s"
        params.append(status)
    
    query += " ORDER BY created_at DESC"
    
    anomalies = await execute_query(query, tuple(params) if params else None, fetch='all')
    return [{**dict(a), "created_at": format_datetime(a["created_at"]), 
             "resolved_at": format_datetime(a.get("resolved_at"))} for a in anomalies]

@api_router.get("/anomalies/pending/count")
async def get_pending_anomalies_count(current_user: dict = Depends(get_current_user)):
    result = await execute_query("SELECT COUNT(*) as count FROM anomalies WHERE status = 'pending'", fetch='one')
    return {"count": result["count"] if result else 0}

@api_router.put("/anomalies/{anomaly_id}/resolve")
async def resolve_anomaly(anomaly_id: str, resolve_data: AnomalyResolve, admin: dict = Depends(require_admin)):
    anomaly = await execute_query("SELECT * FROM anomalies WHERE id = %s", (anomaly_id,), fetch='one')
    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    
    if anomaly["status"] == "resolved":
        raise HTTPException(status_code=400, detail="Anomaly already resolved")
    
    now = datetime.now(timezone.utc)
    await execute_query(
        "UPDATE anomalies SET status = 'resolved', resolved_at = %s, resolved_by = %s, resolved_notes = %s WHERE id = %s",
        (now, admin["user_id"], resolve_data.notes, anomaly_id)
    )
    
    updated = await execute_query("SELECT * FROM anomalies WHERE id = %s", (anomaly_id,), fetch='one')
    return {**dict(updated), "created_at": format_datetime(updated["created_at"]),
            "resolved_at": format_datetime(updated.get("resolved_at"))}

@api_router.delete("/anomalies/{anomaly_id}")
async def delete_anomaly(anomaly_id: str, admin: dict = Depends(require_admin)):
    result = await execute_query("SELECT id FROM anomalies WHERE id = %s", (anomaly_id,), fetch='one')
    if not result:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    await execute_query("DELETE FROM anomalies WHERE id = %s", (anomaly_id,))
    return {"message": "Anomaly deleted successfully"}

# ==================== FUEL REFUELING ROUTES ====================

@api_router.get("/fuel-refuelings", response_model=List[FuelRefuelingResponse])
async def get_fuel_refuelings(vehicle_id: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    if vehicle_id:
        refuelings = await execute_query(
            "SELECT * FROM fuel_refuelings WHERE vehicle_id = %s ORDER BY created_at DESC",
            (vehicle_id,), fetch='all'
        )
    else:
        refuelings = await execute_query("SELECT * FROM fuel_refuelings ORDER BY created_at DESC", fetch='all')
    
    return [{**dict(r), "created_at": format_datetime(r["created_at"]),
             "liters": float(r["liters"]), "value": float(r["value"]), 
             "price_per_liter": float(r["price_per_liter"])} for r in refuelings]

@api_router.post("/fuel-refuelings", response_model=FuelRefuelingResponse, status_code=201)
async def create_fuel_refueling(refueling: FuelRefuelingCreate, current_user: dict = Depends(get_current_user)):
    vehicle = await execute_query("SELECT * FROM vehicles WHERE id = %s", (refueling.vehicle_id,), fetch='one')
    if not vehicle:
        raise HTTPException(status_code=404, detail="Veículo não encontrado")
    
    vehicle_current_km = vehicle.get("current_km", 0) or 0
    
    if refueling.current_km < vehicle_current_km:
        raise HTTPException(
            status_code=400, 
            detail=f"Km informado ({refueling.current_km:,}) não pode ser menor que o km atual do veículo ({vehicle_current_km:,})."
        )
    
    refueling_id = str(uuid.uuid4())
    price_per_liter = refueling.value / refueling.liters if refueling.liters > 0 else 0
    now = datetime.now(timezone.utc)
    
    await execute_query(
        """INSERT INTO fuel_refuelings (id, vehicle_id, current_km, liters, value, fuel_type, price_per_liter, created_at, created_by, created_by_name)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (refueling_id, refueling.vehicle_id, refueling.current_km, refueling.liters, refueling.value,
         refueling.fuel_type, round(price_per_liter, 2), now, current_user["user_id"], current_user.get("name", "Usuário"))
    )
    
    await execute_query("UPDATE vehicles SET current_km = %s WHERE id = %s", (refueling.current_km, refueling.vehicle_id))
    
    return {
        "id": refueling_id,
        "vehicle_id": refueling.vehicle_id,
        "current_km": refueling.current_km,
        "liters": refueling.liters,
        "value": refueling.value,
        "fuel_type": refueling.fuel_type,
        "price_per_liter": round(price_per_liter, 2),
        "created_at": now.isoformat(),
        "created_by": current_user["user_id"],
        "created_by_name": current_user.get("name", "Usuário")
    }

@api_router.delete("/fuel-refuelings/{refueling_id}")
async def delete_fuel_refueling(refueling_id: str, admin: dict = Depends(require_admin)):
    result = await execute_query("SELECT id FROM fuel_refuelings WHERE id = %s", (refueling_id,), fetch='one')
    if not result:
        raise HTTPException(status_code=404, detail="Registro de abastecimento não encontrado")
    await execute_query("DELETE FROM fuel_refuelings WHERE id = %s", (refueling_id,))
    return {"message": "Registro de abastecimento excluído com sucesso"}

# ==================== VEHICLE REPORT ROUTES ====================

@api_router.get("/vehicles/{vehicle_id}/report")
async def get_vehicle_report(vehicle_id: str, current_user: dict = Depends(get_current_user)):
    vehicle = await execute_query("SELECT * FROM vehicles WHERE id = %s", (vehicle_id,), fetch='one')
    if not vehicle:
        raise HTTPException(status_code=404, detail="Veículo não encontrado")
    
    refuelings = await execute_query(
        "SELECT * FROM fuel_refuelings WHERE vehicle_id = %s ORDER BY created_at DESC",
        (vehicle_id,), fetch='all'
    )
    
    refuelings_list = [{**dict(r), "created_at": format_datetime(r["created_at"]),
                        "liters": float(r["liters"]), "value": float(r["value"]),
                        "price_per_liter": float(r["price_per_liter"])} for r in refuelings]
    
    total_liters = sum(r["liters"] for r in refuelings_list)
    total_value = sum(r["value"] for r in refuelings_list)
    total_refuelings = len(refuelings_list)
    
    avg_consumption = 0.0
    if len(refuelings_list) >= 2:
        sorted_refuelings = sorted(refuelings_list, key=lambda x: x["current_km"])
        total_km_driven = 0
        total_liters_used = 0
        for i in range(1, len(sorted_refuelings)):
            km_diff = sorted_refuelings[i]["current_km"] - sorted_refuelings[i-1]["current_km"]
            if km_diff > 0:
                total_km_driven += km_diff
                total_liters_used += sorted_refuelings[i]["liters"]
        if total_liters_used > 0:
            avg_consumption = round(total_km_driven / total_liters_used, 2)
    
    fuel_breakdown = {}
    for r in refuelings_list:
        fuel_type = r["fuel_type"]
        if fuel_type not in fuel_breakdown:
            fuel_breakdown[fuel_type] = {"liters": 0, "value": 0, "count": 0}
        fuel_breakdown[fuel_type]["liters"] += r["liters"]
        fuel_breakdown[fuel_type]["value"] += r["value"]
        fuel_breakdown[fuel_type]["count"] += 1
    
    return {
        "vehicle": calculate_vehicle_status(dict(vehicle)),
        "refuelings": refuelings_list,
        "statistics": {
            "total_liters": round(total_liters, 2),
            "total_value": round(total_value, 2),
            "total_refuelings": total_refuelings,
            "avg_consumption_km_per_liter": avg_consumption,
            "fuel_breakdown": fuel_breakdown
        }
    }

# ==================== DASHBOARD ROUTES ====================

@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    vehicles = await execute_query("SELECT * FROM vehicles", fetch='all')
    
    vehicles_with_status = [calculate_vehicle_status(dict(v)) for v in vehicles]
    
    vehicles_warning = [v for v in vehicles_with_status if v["oil_status"] == "warning" or v["tire_balance_status"] == "warning" or v["tire_alignment_status"] == "warning"]
    vehicles_ok = [v for v in vehicles_with_status if v not in vehicles_warning]
    
    return {
        "total_vehicles": len(vehicles),
        "vehicles_ok": len(vehicles_ok),
        "vehicles_warning": len(vehicles_warning),
        "vehicles_needing_attention": vehicles_warning
    }

# ==================== SETUP ====================

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    await get_pool()
    logger.info("GFA Fleet Control API started - MySQL Database Connected")

@app.on_event("shutdown")
async def shutdown_event():
    global pool
    if pool:
        pool.close()
        await pool.wait_closed()
