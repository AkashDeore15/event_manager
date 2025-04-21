# tests/test_database.py
import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import Database

@pytest.mark.asyncio
async def test_database_initialization():
    """Test that the Database class is initialized correctly."""
    # Reset the class variables to simulate a fresh state
    Database._engine = None
    Database._session_factory = None
    
    # Mock create_async_engine and sessionmaker
    with patch('app.database.create_async_engine') as mock_engine, \
         patch('app.database.sessionmaker') as mock_sessionmaker:
         
        # Set up mock return values
        mock_engine.return_value = MagicMock()
        mock_sessionmaker.return_value = MagicMock()
        
        # Initialize the database
        db_url = "postgresql+asyncpg://user:password@localhost:5432/testdb"
        Database.initialize(db_url, echo=True)
        
        # Check that create_async_engine was called with correct args
        mock_engine.assert_called_once_with(db_url, echo=True, future=True)
        
        # Check that sessionmaker was called with correct args
        mock_sessionmaker.assert_called_once()
        sessionmaker_kwargs = mock_sessionmaker.call_args[1]
        assert sessionmaker_kwargs['bind'] == mock_engine.return_value
        assert sessionmaker_kwargs['class_'] == AsyncSession
        assert sessionmaker_kwargs['expire_on_commit'] is False
        assert sessionmaker_kwargs['future'] is True

@pytest.mark.asyncio
async def test_get_session_factory_initialized():
    """Test getting the session factory when it's initialized."""
    # Setup mock session factory
    Database._session_factory = MagicMock()
    
    # Get the session factory
    session_factory = Database.get_session_factory()
    
    # Verify we got the mock session factory
    assert session_factory == Database._session_factory

@pytest.mark.asyncio
async def test_get_session_factory_not_initialized():
    """Test getting session factory when not initialized raises an error."""
    # Ensure the session factory is not initialized
    Database._session_factory = None
    
    # Check that it raises a ValueError
    with pytest.raises(ValueError) as exc_info:
        Database.get_session_factory()
    
    # Verify the error message
    assert "Database not initialized" in str(exc_info.value)