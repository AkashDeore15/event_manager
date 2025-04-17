from builtins import range
import pytest
from sqlalchemy import select
from app.dependencies import get_settings
from app.models.user_model import User
from app.services.user_service import UserService
from uuid import UUID

pytestmark = pytest.mark.asyncio

# Reusable test data
@pytest.fixture
def valid_user_data():
    return {
        "email": "valid_user@example.com",
        "password": "ValidPassword123!",
    }

@pytest.fixture
def invalid_user_data():
    return {
        "nickname": "",  # Invalid nickname
        "email": "invalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }

@pytest.fixture
def update_profile_data():
    return {
        "first_name": "UpdatedFirst",
        "last_name": "UpdatedLast",
        "bio": "Updated bio information"
    }

@pytest.fixture
def update_urls_data():
    return {
        "github_profile_url": "https://github.com/newusername",
        "linkedin_profile_url": "https://linkedin.com/in/newusername"
    }

# Create/Register User Tests
class TestUserCreation:
    async def test_create_user_with_valid_data(self, db_session, email_service, valid_user_data):
        user = await UserService.create(db_session, valid_user_data, email_service)
        assert user is not None
        assert user.email == valid_user_data["email"]

    async def test_create_user_with_invalid_data(self, db_session, email_service, invalid_user_data):
        user = await UserService.create(db_session, invalid_user_data, email_service)
        assert user is None

    async def test_register_user_with_valid_data(self, db_session, email_service, valid_user_data):
        user = await UserService.register_user(db_session, valid_user_data, email_service)
        assert user is not None
        assert user.email == valid_user_data["email"]

    async def test_register_user_with_invalid_data(self, db_session, email_service, invalid_user_data):
        user = await UserService.register_user(db_session, invalid_user_data, email_service)
        assert user is None

# Fetch User Tests
class TestUserFetching:
    # Parametrized test for fetching by different identifiers
    @pytest.mark.parametrize("fetch_method, field_name", [
        (UserService.get_by_id, "id"),
        (UserService.get_by_nickname, "nickname"),
        (UserService.get_by_email, "email"),
    ])
    async def test_get_user_exists(self, db_session, user, fetch_method, field_name):
        field_value = getattr(user, field_name)
        retrieved_user = await fetch_method(db_session, field_value)
        assert retrieved_user is not None
        assert getattr(retrieved_user, field_name) == field_value

    @pytest.mark.parametrize("fetch_method, invalid_value", [
        (UserService.get_by_id, "non-existent-id"),
        (UserService.get_by_nickname, "non_existent_nickname"),
        (UserService.get_by_email, "non_existent_email@example.com"),
    ])
    async def test_get_user_does_not_exist(self, db_session, fetch_method, invalid_value):
        retrieved_user = await fetch_method(db_session, invalid_value)
        assert retrieved_user is None

# Update User Tests
class TestUserUpdate:
    async def test_update_single_field(self, db_session, user):
        new_email = "updated_email@example.com"
        updated_user = await UserService.update(db_session, user.id, {"email": new_email})
        assert updated_user is not None
        assert updated_user.email == new_email

    async def test_update_multiple_fields(self, db_session, user, update_profile_data):
        updated_user = await UserService.update(db_session, user.id, update_profile_data)
        assert updated_user is not None
        for field, value in update_profile_data.items():
            assert getattr(updated_user, field) == value

    async def test_update_profile_urls(self, db_session, user, update_urls_data):
        updated_user = await UserService.update(db_session, user.id, update_urls_data)
        assert updated_user is not None
        for field, value in update_urls_data.items():
            assert getattr(updated_user, field) == value

    async def test_update_invalid_data(self, db_session, user):
        updated_user = await UserService.update(db_session, user.id, {"email": "invalidemail"})
        assert updated_user is None

    async def test_update_empty_data(self, db_session, user):
        updated_user = await UserService.update(db_session, user.id, {})
        if updated_user:
            assert updated_user.id == user.id

# User Management Tests
class TestUserManagement:
    async def test_delete_user_exists(self, db_session, user):
        deletion_success = await UserService.delete(db_session, user.id)
        assert deletion_success is True

    async def test_delete_user_does_not_exist(self, db_session):
        non_existent_user_id = "non-existent-id"
        deletion_success = await UserService.delete(db_session, non_existent_user_id)
        assert deletion_success is False

    async def test_list_users_with_pagination(self, db_session, users_with_same_role_50_users):
        users_page_1 = await UserService.list_users(db_session, skip=0, limit=10)
        users_page_2 = await UserService.list_users(db_session, skip=10, limit=10)
        assert len(users_page_1) == 10
        assert len(users_page_2) == 10
        assert users_page_1[0].id != users_page_2[0].id

# Authentication Tests
class TestAuthentication:
    async def test_login_user_successful(self, db_session, verified_user):
        logged_in_user = await UserService.login_user(
            db_session, verified_user.email, "MySuperPassword$1234"
        )
        assert logged_in_user is not None

    async def test_login_user_incorrect_email(self, db_session):
        user = await UserService.login_user(db_session, "nonexistentuser@noway.com", "Password123!")
        assert user is None

    async def test_login_user_incorrect_password(self, db_session, user):
        user = await UserService.login_user(db_session, user.email, "IncorrectPassword!")
        assert user is None

    async def test_account_lock_after_failed_logins(self, db_session, verified_user):
        max_login_attempts = get_settings().max_login_attempts
        for _ in range(max_login_attempts):
            await UserService.login_user(db_session, verified_user.email, "wrongpassword")
        
        is_locked = await UserService.is_account_locked(db_session, verified_user.email)
        assert is_locked, "Account should be locked after maximum failed login attempts"

    async def test_reset_password(self, db_session, user):
        new_password = "NewPassword123!"
        reset_success = await UserService.reset_password(db_session, user.id, new_password)
        assert reset_success is True

    async def test_verify_email_with_token(self, db_session, user):
        token = "valid_token_example"
        user.verification_token = token
        await db_session.commit()
        result = await UserService.verify_email_with_token(db_session, user.id, token)
        assert result is True

    async def test_unlock_user_account(self, db_session, locked_user):
        unlocked = await UserService.unlock_user_account(db_session, locked_user.id)
        assert unlocked, "The account should be unlocked"
        refreshed_user = await UserService.get_by_id(db_session, locked_user.id)
        assert not refreshed_user.is_locked, "The user should no longer be locked"