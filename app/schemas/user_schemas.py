from builtins import ValueError, any, bool, str
from pydantic import BaseModel, EmailStr, Field, validator, root_validator
from typing import Optional, List, Callable, Dict, Union, Type
from datetime import datetime
from enum import Enum
import uuid
import re

from app.utils.nickname_gen import generate_nickname

class UserRole(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"

class URLValidator:
    """Centralized URL validation with configurable patterns for different URL types."""
    
    # Basic URL format shared by all URL types
    BASE_URL_PATTERN = r'^https?:\/\/[^\s/$.?#].[^\s]*$'
    
    # Specific URL patterns
    URL_PATTERNS = {
        'github': r'^https?:\/\/(www\.)?github\.com\/[\w-]+$',
        'linkedin': r'^https?:\/\/(www\.)?linkedin\.com\/in\/[\w-]+$',
        'profile': BASE_URL_PATTERN  # Default to basic URL validation for profile pictures
    }
    
    # Custom error messages
    ERROR_MESSAGES = {
        'github': 'Invalid GitHub URL format. Should be https://github.com/{username}',
        'linkedin': 'Invalid LinkedIn URL format. Should be https://linkedin.com/in/{username}',
        'profile': 'Invalid URL format',
        'base': 'Invalid URL format'
    }
    
    @classmethod
    def validate_url(cls, url: Optional[str], url_type: str) -> Optional[str]:
        """Validate a URL against a specific pattern.
        
        Args:
            url: URL to validate
            url_type: Type of URL ('github', 'linkedin', 'profile')
            
        Returns:
            The URL if valid, or None if the input was None
            
        Raises:
            ValueError: If the URL doesn't match the required pattern
        """
        if url is None:
            return None
            
        # Basic URL format validation
        if not re.match(cls.BASE_URL_PATTERN, url):
            raise ValueError(cls.ERROR_MESSAGES['base'])
            
        # Specific validation if we have a pattern for this URL type
        pattern = cls.URL_PATTERNS.get(url_type)
        if pattern and pattern != cls.BASE_URL_PATTERN and not re.match(pattern, url):
            raise ValueError(cls.ERROR_MESSAGES[url_type])
        
        return url

class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname())
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")

    # Use the centralized validator for each URL type
    @validator('profile_picture_url', pre=True)
    def validate_profile_url(cls, v):
        return URLValidator.validate_url(v, 'profile')
        
    @validator('github_profile_url', pre=True)
    def validate_github_url(cls, v):
        return URLValidator.validate_url(v, 'github')
        
    @validator('linkedin_profile_url', pre=True)
    def validate_linkedin_url(cls, v):
        return URLValidator.validate_url(v, 'linkedin')
 
    class Config:
        from_attributes = True

class UserCreate(UserBase):
    email: EmailStr = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

class UserUpdate(UserBase):
    email: Optional[EmailStr] = Field(None, example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example="john_doe123")
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update")
        return values

class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    role: UserRole = Field(default=UserRole.AUTHENTICATED, example="AUTHENTICATED")
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname())    
    is_professional: Optional[bool] = Field(default=False, example=True)

class LoginRequest(BaseModel):
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

class ErrorResponse(BaseModel):
    error: str = Field(..., example="Not Found")
    details: Optional[str] = Field(None, example="The requested resource was not found.")

class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(..., example=[{
        "id": uuid.uuid4(), "nickname": generate_nickname(), "email": "john.doe@example.com",
        "first_name": "John", "bio": "Experienced developer", "role": "AUTHENTICATED",
        "last_name": "Doe", "profile_picture_url": "https://example.com/profiles/john.jpg", 
        "linkedin_profile_url": "https://linkedin.com/in/johndoe", 
        "github_profile_url": "https://github.com/johndoe"
    }])
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)