# tests/test_api/test_additional_user_routes.py
import pytest
from unittest.mock import patch, MagicMock
from httpx import AsyncClient
from uuid import uuid4
from app.main import app
from app.routers.user_routes import create_user_response, get_user_or_404

@pytest.mark.asyncio
async def test_register_new_user(async_client):
    """Test user registration endpoint."""
    user_data = {
        "email": "newuser@example.com",
        "password": "SecurePassword123!",
        "nickname": "newuser123"
    }
    
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 200
    assert response.json()["email"] == user_data["email"]
    # Don't check nickname equality since it's auto-generated
    # Just verify it exists and is a string
    assert "nickname" in response.json()
    assert isinstance(response.json()["nickname"], str)

@pytest.mark.asyncio
async def test_verify_email_success(async_client, unverified_user, db_session):
    """Test successful email verification."""
    # Set a verification token for the user
    token = "test_verification_token"
    unverified_user.verification_token = token
    await db_session.commit()
    
    # Call the verification endpoint
    response = await async_client.get(f"/verify-email/{unverified_user.id}/{token}")
    
    # Check the response
    assert response.status_code == 200
    assert response.json()["message"] == "Email verified successfully"

@pytest.mark.asyncio
async def test_verify_email_invalid_token(async_client, unverified_user):
    """Test email verification with invalid token."""
    invalid_token = "invalid_token"
    
    # Call the verification endpoint with an invalid token
    response = await async_client.get(f"/verify-email/{unverified_user.id}/{invalid_token}")
    
    # Check the response
    assert response.status_code == 400
    assert "Invalid or expired verification token" in response.json()["detail"]

@pytest.mark.asyncio
async def test_check_password_strength_valid(async_client):
    """Test password strength checker with valid password."""
    password_data = {"password": "ValidPassword123!"}
    
    response = await async_client.post("/check-password-strength/", json=password_data)
    
    assert response.status_code == 200
    assert response.json()["message"] == "Password meets strength requirements"

@pytest.mark.asyncio
async def test_check_password_strength_invalid(async_client):
    """Test password strength checker with invalid password."""
    password_data = {"password": "weak"}
    
    response = await async_client.post("/check-password-strength/", json=password_data)
    
    assert response.status_code == 400
    assert "Password must be at least 8 characters long" in response.json()["detail"]

@pytest.mark.asyncio
async def test_create_user_response_with_request():
    """Test the create_user_response helper function with a request object."""
    # Create a mock user
    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_user.nickname = "testuser"
    mock_user.email = "test@example.com"
    mock_user.first_name = "Test"
    mock_user.last_name = "User"
    mock_user.bio = "Test bio"
    mock_user.profile_picture_url = "https://example.com/pic.jpg"
    mock_user.github_profile_url = "https://github.com/testuser"
    mock_user.linkedin_profile_url = "https://linkedin.com/in/testuser"
    mock_user.role = "AUTHENTICATED"
    mock_user.last_login_at = None
    mock_user.created_at = None
    mock_user.updated_at = None
    
    # Create a mock request
    mock_request = MagicMock()
    
    # Patch the create_user_links function
    with patch('app.routers.user_routes.create_user_links', return_value=["link1", "link2"]):
        # Call the function
        response = create_user_response(mock_user, mock_request)
        
        # Check the response
        assert response.id == mock_user.id
        assert response.nickname == mock_user.nickname
        assert response.email == mock_user.email
        assert hasattr(response, "links")
        assert response.links == ["link1", "link2"]

@pytest.mark.asyncio
async def test_create_user_response_without_request():
    """Test the create_user_response helper function without a request object."""
    # Create a mock user
    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_user.nickname = "testuser"
    mock_user.email = "test@example.com"
    mock_user.first_name = "Test"
    mock_user.last_name = "User"
    mock_user.bio = "Test bio"
    mock_user.profile_picture_url = "https://example.com/pic.jpg"
    mock_user.github_profile_url = "https://github.com/testuser"
    mock_user.linkedin_profile_url = "https://linkedin.com/in/testuser"
    mock_user.role = "AUTHENTICATED"
    mock_user.last_login_at = None
    mock_user.created_at = None
    mock_user.updated_at = None
    
    # Call the function without a request
    response = create_user_response(mock_user)
    
    # Check the response
    assert response.id == mock_user.id
    assert response.nickname == mock_user.nickname
    assert response.email == mock_user.email
    assert not hasattr(response, "links")

@pytest.mark.asyncio
async def test_get_user_or_404_found(db_session):
    """Test get_user_or_404 helper function when user is found."""
    # Create a mock user
    user_id = uuid4()
    
    # Mock the UserService.get_by_id function to return a user
    with patch('app.services.user_service.UserService.get_by_id', return_value=MagicMock()) as mock_get_by_id:
        # Call the function
        user = await get_user_or_404(db_session, user_id)
        
        # Check that the function returned the mock user
        assert user is not None
        mock_get_by_id.assert_called_once_with(db_session, user_id)

@pytest.mark.asyncio
async def test_get_user_or_404_not_found(db_session):
    """Test get_user_or_404 helper function when user is not found."""
    # Create a user ID
    user_id = uuid4()
    
    # Mock the UserService.get_by_id function to return None
    with patch('app.services.user_service.UserService.get_by_id', return_value=None) as mock_get_by_id:
        # Call the function, which should raise an HTTPException
        with pytest.raises(Exception) as exc_info:
            await get_user_or_404(db_session, user_id)
        
        # Check that the function raised an HTTPException with status code 404
        assert "404" in str(exc_info.value)
        assert "User not found" in str(exc_info.value)
        mock_get_by_id.assert_called_once_with(db_session, user_id)