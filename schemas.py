"""
Database Schemas for App

Each Pydantic model represents a MongoDB collection. The collection name is the lowercase of the class name.
"""
from typing import Optional, List, Dict
from pydantic import BaseModel, Field

# -----------------
# Auth and Users
# -----------------
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="Password hash with salt")
    salt: str = Field(..., description="Password salt")
    is_active: bool = Field(True)
    avatar_url: Optional[str] = None

class Session(BaseModel):
    user_id: str
    token: str
    user_agent: Optional[str] = None
    ip: Optional[str] = None
    expires_at: Optional[str] = None

# -----------------
# SaaS Core
# -----------------
class Organization(BaseModel):
    name: str
    slug: Optional[str] = None
    owner_id: str

class Membership(BaseModel):
    org_id: str
    user_id: str
    role: str = Field("member", description="owner | admin | member")

class Project(BaseModel):
    org_id: str
    name: str
    description: Optional[str] = None
    status: str = Field("active")

class Plan(BaseModel):
    key: str = Field(..., description="unique plan key, e.g., starter, pro, scale")
    name: str
    price_monthly: float = Field(ge=0)
    features: List[str] = Field(default_factory=list)

class Subscription(BaseModel):
    org_id: str
    plan_key: str
    status: str = Field("active", description="active | canceled | past_due")
    provider: str = Field("internal", description="billing provider id or name")

# -----------------
# Legacy Price Comparison (optional)
# -----------------
class Category(BaseModel):
    slug: str = Field(..., description="url-friendly unique id")
    title: str
    icon: Optional[str] = None
    parent_slug: Optional[str] = Field(None, description="Parent category slug for hierarchy")

class Product(BaseModel):
    sku: str = Field(..., description="Unique product SKU")
    title: str
    description: Optional[str] = None
    category_slug: str
    brand: Optional[str] = None
    images: List[str] = Field(default_factory=list)
    attributes: Dict[str, str] = Field(default_factory=dict)

class Offer(BaseModel):
    product_sku: str
    vendor: str
    vendor_url: str
    price: float = Field(..., ge=0)
    shipping: float = Field(0, ge=0)
    currency: str = Field("USD")
    in_stock: bool = True
    rating: Optional[float] = Field(None, ge=0, le=5)

class Favorite(BaseModel):
    user_id: str
    product_sku: str
