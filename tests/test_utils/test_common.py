# tests/test_utils/test_common.py
import os
import logging
import pytest
from unittest.mock import patch, MagicMock
from app.utils.common import setup_logging
from app.dependencies import get_settings

@pytest.mark.asyncio
async def test_setup_logging():
    """Test that the setup_logging function configures logging correctly."""
    # Create a mock for fileConfig to avoid actual file configuration
    with patch('logging.config.fileConfig') as mock_fileconfig:
        # Call the function
        setup_logging()
        
        # Check that fileConfig was called with the expected path
        mock_fileconfig.assert_called_once()
        
        # Extract the path argument from the call
        path_arg = mock_fileconfig.call_args[0][0]
        
        # Verify the path looks like a properly normalized logging.conf path
        assert os.path.basename(path_arg) == 'logging.conf'
        # Check the kwargs dict directly instead of string comparison
        assert 'disable_existing_loggers' in mock_fileconfig.call_args[1]
        assert mock_fileconfig.call_args[1]['disable_existing_loggers'] is False