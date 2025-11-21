import os
import hashlib
import secrets
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, Header, Path, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from database import db, create_document, get_documents

app = FastAPI(title="SaaS Platform API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------
# Utility functions
# -----------------

def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return dk.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    computed, _ = hash_password(password, salt)
    return secrets.compare_digest(computed, password_hash)


# -----------------
# Pydantic models
# -----------------
class SignupRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class SessionResponse(BaseModel):
    token: str
    user: Dict[str, Any]


# -----------------
# Auth Endpoints
# -----------------
@app.post("/auth/signup", response_model=SessionResponse)
def signup(payload: SignupRequest):
    existing = list(db["user"].find({"email": payload.email})) if db else []
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash, salt = hash_password(payload.password)
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": password_hash,
        "salt": salt,
        "is_active": True,
        "avatar_url": None,
    }
    user_id = create_document("user", user_doc)

    token = secrets.token_urlsafe(32)
    session_doc = {"user_id": user_id, "token": token}
    create_document("session", session_doc)

    user_doc["_id"] = user_id
    user_public = {k: v for k, v in user_doc.items() if k not in ("password_hash", "salt")}
    return {"token": token, "user": user_public}


@app.post("/auth/login", response_model=SessionResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email}) if db else None
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user.get("password_hash"), user.get("salt")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = secrets.token_urlsafe(32)
    create_document("session", {"user_id": str(user.get("_id")), "token": token})

    user_public = {k: v for k, v in user.items() if k not in ("password_hash", "salt")}
    user_public["_id"] = str(user_public["_id"]) if "_id" in user_public else None
    return {"token": token, "user": user_public}


# --------------
# Dependency
# --------------
class AuthedUser(BaseModel):
    user_id: str

def get_user_by_token(authorization: Optional[str] = Header(default=None)) -> AuthedUser:
    if not authorization:
        raise HTTPException(401, detail="Missing token")
    token = authorization.replace("Bearer ", "")
    sess = db["session"].find_one({"token": token}) if db else None
    if not sess:
        raise HTTPException(401, detail="Invalid token")
    return AuthedUser(user_id=sess.get("user_id"))


# --------------
# SaaS: Orgs, Memberships, Projects, Plans, Subscriptions
# --------------
class OrgCreate(BaseModel):
    name: str
    slug: Optional[str] = None

class OrgInvite(BaseModel):
    user_id: str
    role: str = Field("member")

class ProjectCreate(BaseModel):
    org_id: str
    name: str
    description: Optional[str] = None

class PlanCreate(BaseModel):
    key: str
    name: str
    price_monthly: float = Field(ge=0)
    features: List[str] = []

class SubscribeRequest(BaseModel):
    org_id: str
    plan_key: str


def ensure_member(org_id: str, user_id: str) -> Dict[str, Any]:
    if db is None:
        raise HTTPException(500, "Database not configured")
    mem = db["membership"].find_one({"org_id": org_id, "user_id": user_id})
    if not mem:
        raise HTTPException(403, "Not a member of this organization")
    return mem


@app.post("/orgs")
def create_org(body: OrgCreate, au: AuthedUser = Depends(get_user_by_token)):
    org_doc = {"name": body.name, "slug": body.slug, "owner_id": au.user_id}
    org_id = create_document("organization", org_doc)
    create_document("membership", {"org_id": org_id, "user_id": au.user_id, "role": "owner"})
    return {"id": org_id}


@app.get("/orgs")
def list_orgs(au: AuthedUser = Depends(get_user_by_token)):
    if db is None:
        raise HTTPException(500, "Database not configured")
    mems = list(db["membership"].find({"user_id": au.user_id}))
    org_ids = [m.get("org_id") for m in mems]
    orgs = list(db["organization"].find({"_id": {"$in": [*map(lambda x: db["organization"].database.client.get_default_database().codec_options.document_class().get("_id", x), org_ids)]}})) if False else list(db["organization"].find({}))
    # Fallback simple approach: fetch orgs and filter by id strings
    orgs = [o for o in orgs if str(o.get("_id")) in set(org_ids)]
    for o in orgs:
        o["_id"] = str(o.get("_id"))
    return {"items": orgs}


@app.get("/orgs/{org_id}/members")
def list_members(org_id: str = Path(...), au: AuthedUser = Depends(get_user_by_token)):
    ensure_member(org_id, au.user_id)
    items = get_documents("membership", {"org_id": org_id}, 500)
    for it in items:
        it["_id"] = str(it.get("_id"))
    return {"items": items}


@app.post("/orgs/{org_id}/invite")
def invite_member(org_id: str, body: OrgInvite, au: AuthedUser = Depends(get_user_by_token)):
    mem = ensure_member(org_id, au.user_id)
    if mem.get("role") not in ("owner", "admin"):
        raise HTTPException(403, "Insufficient role")
    exists = db["membership"].find_one({"org_id": org_id, "user_id": body.user_id}) if db else None
    if exists:
        return {"status": "exists"}
    mid = create_document("membership", {"org_id": org_id, "user_id": body.user_id, "role": body.role})
    return {"id": mid}


@app.post("/projects")
def create_project(body: ProjectCreate, au: AuthedUser = Depends(get_user_by_token)):
    ensure_member(body.org_id, au.user_id)
    pid = create_document("project", {"org_id": body.org_id, "name": body.name, "description": body.description, "status": "active"})
    return {"id": pid}


@app.get("/projects")
def list_projects(org_id: str = Query(...), au: AuthedUser = Depends(get_user_by_token)):
    ensure_member(org_id, au.user_id)
    items = get_documents("project", {"org_id": org_id}, 500)
    for it in items:
        it["_id"] = str(it.get("_id"))
    return {"items": items}


@app.post("/plans")
def create_plan(body: PlanCreate, au: AuthedUser = Depends(get_user_by_token)):
    # Simple protection: only allow creating plan if user email contains 'admin' (demo)
    user = db["user"].find_one({"_id": {"$in": []}})  # not used; keeping API simple
    exists = db["plan"].find_one({"key": body.key}) if db else None
    if exists:
        raise HTTPException(400, "Plan key exists")
    pid = create_document("plan", body.model_dump())
    return {"id": pid}


@app.get("/plans")
def list_plans():
    items = get_documents("plan", {}, 100)
    # Seed defaults if empty
    if not items:
        for p in [
            {"key": "starter", "name": "Starter", "price_monthly": 0, "features": ["1 proje", "Temel raporlar"]},
            {"key": "pro", "name": "Pro", "price_monthly": 29, "features": ["10 proje", "Öncelikli destek"]},
            {"key": "scale", "name": "Scale", "price_monthly": 99, "features": ["Sınırsız proje", "Gelişmiş entegrasyonlar"]},
        ]:
            create_document("plan", p)
        items = get_documents("plan", {}, 100)
    for it in items:
        it["_id"] = str(it.get("_id"))
    return {"items": items}


@app.post("/subscriptions")
def subscribe(body: SubscribeRequest, au: AuthedUser = Depends(get_user_by_token)):
    ensure_member(body.org_id, au.user_id)
    # set active subscription for org
    sub = db["subscription"].find_one({"org_id": body.org_id}) if db else None
    if sub:
        db["subscription"].update_one({"_id": sub.get("_id")}, {"$set": {"plan_key": body.plan_key, "status": "active"}})
        return {"id": str(sub.get("_id")), "updated": True}
    sid = create_document("subscription", {"org_id": body.org_id, "plan_key": body.plan_key, "status": "active", "provider": "internal"})
    return {"id": sid}


@app.get("/subscriptions")
def get_subscription(org_id: str = Query(...), au: AuthedUser = Depends(get_user_by_token)):
    ensure_member(org_id, au.user_id)
    sub = db["subscription"].find_one({"org_id": org_id}) if db else None
    if not sub:
        return {"item": None}
    sub["_id"] = str(sub.get("_id"))
    return {"item": sub}


# --------------
# Legacy Catalog/Search/Offers/Favorites (optional demo endpoints)
# --------------
class CategoryCreate(BaseModel):
    slug: str
    title: str
    icon: Optional[str] = None
    parent_slug: Optional[str] = None


class ProductCreate(BaseModel):
    sku: str
    title: str
    description: Optional[str] = None
    category_slug: str
    brand: Optional[str] = None
    images: List[str] = []
    attributes: Dict[str, str] = {}


class OfferCreate(BaseModel):
    product_sku: str
    vendor: str
    vendor_url: str
    price: float
    shipping: float = 0
    currency: str = "USD"
    in_stock: bool = True
    rating: Optional[float] = None


@app.post("/categories")
def create_category(cat: CategoryCreate):
    exists = db["category"].find_one({"slug": cat.slug}) if db else None
    if exists:
        raise HTTPException(400, "Category already exists")
    cid = create_document("category", cat.model_dump())
    return {"id": cid}


@app.get("/categories")
def list_categories(parent_slug: Optional[str] = None, limit: int = 100):
    filt = {"parent_slug": parent_slug} if parent_slug is not None else {}
    items = get_documents("category", filt, limit)
    for it in items:
        it["_id"] = str(it.get("_id"))
    return {"items": items}


@app.post("/products")
def create_product(p: ProductCreate):
    exists = db["product"].find_one({"sku": p.sku}) if db else None
    if exists:
        raise HTTPException(400, "Product SKU already exists")
    pid = create_document("product", p.model_dump())
    return {"id": pid}


@app.get("/products")
def list_products(category_slug: Optional[str] = None, q: Optional[str] = None, limit: int = 50):
    filt: Dict[str, Any] = {}
    if category_slug:
        filt["category_slug"] = category_slug
    if q:
        filt["title"] = {"$regex": q, "$options": "i"}
    items = get_documents("product", filt, limit)
    for it in items:
        it["_id"] = str(it.get("_id"))
    return {"items": items}


@app.post("/offers")
def create_offer(o: OfferCreate):
    prod = db["product"].find_one({"sku": o.product_sku}) if db else None
    if not prod:
        raise HTTPException(400, "Product not found for given SKU")
    oid = create_document("offer", o.model_dump())
    return {"id": oid}


@app.get("/offers/{sku}")
def list_offers_for_product(sku: str, limit: int = 50):
    items = get_documents("offer", {"product_sku": sku}, limit)
    for it in items:
        it["_id"] = str(it.get("_id"))
    best = None
    for it in items:
        total = float(it.get("price", 0)) + float(it.get("shipping", 0))
        if best is None or total < best.get("total", 1e18):
            best = {"vendor": it.get("vendor"), "total": total, "currency": it.get("currency", "USD")}
    return {"items": items, "best": best}


class FavoriteRequest(BaseModel):
    product_sku: str


@app.post("/favorites")
def add_favorite(fav: FavoriteRequest, au: AuthedUser = Depends(get_user_by_token)):
    exists = db["favorite"].find_one({"user_id": au.user_id, "product_sku": fav.product_sku}) if db else None
    if exists:
        return {"status": "exists"}
    fid = create_document("favorite", {"user_id": au.user_id, "product_sku": fav.product_sku})
    return {"id": fid}


@app.get("/favorites")
def list_favorites(au: AuthedUser = Depends(get_user_by_token)):
    items = get_documents("favorite", {"user_id": au.user_id}, 500)
    for it in items:
        it["_id"] = str(it.get("_id"))
    return {"items": items}


# ---------
# Utilities
# ---------
@app.get("/")
def read_root():
    return {"message": "SaaS Platform API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available" if db is None else "✅ Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:100]}"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
