"""
Database Schemas for Price Comparison App

Each Pydantic model represents a MongoDB collection. The collection name is the lowercase of the class name.
"""
from typing import Optional, List, Dict
from pydantic import BaseModel, Field

# Auth and Users
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

# Catalog
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
