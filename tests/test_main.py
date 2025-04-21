# tests/test_main.py
import pytest
from unittest.mock import patch, MagicMock
from fastapi import FastAPI
from starlette.responses import JSONResponse
from app.main import app, exception_handler, startup_event

@pytest.mark.asyncio
async def test_app_instance():
    """Test that the app instance is properly configured."""
    assert isinstance(app, FastAPI)
    assert app.title == "User Management"
    # Check that routes are included
    assert any(route.path == "/users/" for route in app.routes)
    assert any(route.path == "/login/" for route in app.routes)
    assert any(route.path == "/register/" for route in app.routes)

@pytest.mark.asyncio
async def test_startup_event():
    """Test the startup event initializes the database."""
    with patch('app.dependencies.get_settings') as mock_get_settings, \
         patch('app.database.Database.initialize') as mock_initialize:
        
        # Create a mock settings object with the ACTUAL values used
        mock_settings = MagicMock()
        mock_settings.database_url = "postgresql+asyncpg://user:password@localhost:5432/myappdb"
        mock_settings.debug = False
        mock_get_settings.return_value = mock_settings
        
        # Call the startup event
        await startup_event()
        
        # Check that Database.initialize was called with the correct args
        mock_initialize.assert_called_once_with(mock_settings.database_url, mock_settings.debug)

@pytest.mark.asyncio
async def test_exception_handler():
    """Test the global exception handler."""
    # Create a mock request
    mock_request = MagicMock()
    
    # Create a test exception
    test_exception = Exception("Test error message")
    
    # Call the exception handler
    response = await exception_handler(mock_request, test_exception)
    
    # Check the response
    assert isinstance(response, JSONResponse)
    assert response.status_code == 500
    assert response.body.decode().find("An unexpected error occurred") > 0

@pytest.mark.asyncio
async def test_app_routes():
    """Test that the app has the expected routes."""
    # Check that user routes are included
    user_routes = [route for route in app.routes if route.path.startswith("/users")]
    assert len(user_routes) > 0
    
    # Check that authentication routes are included
    auth_routes = [route for route in app.routes if route.path in ["/login/", "/register/"]]
    assert len(auth_routes) == 2