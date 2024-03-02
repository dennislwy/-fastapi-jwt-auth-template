import pytest
from datetime import datetime, timedelta
from app.auth.session import add, exists, update_last_activity, remove, retrieve_sessions_by_userid

@pytest.mark.asyncio
async def test_add():
    user_id = "user123"
    session_id = "session123"
    value = {"name": "John Doe"}
    ttl = 3600

    result = await add(user_id, session_id, value, ttl)

    assert result is True

@pytest.mark.asyncio
async def test_exists():
    user_id = "user123"
    session_id = "session123"

    result = await exists(user_id, session_id)

    assert result is True

@pytest.mark.asyncio
async def test_update_last_activity():
    payload = {"sub": "user123", "sid": "session123"}

    await update_last_activity(payload)

    # Assert that the last_active timestamp has been updated
    # You can modify this assertion based on your specific implementation
    assert datetime.utcnow() - value.last_active < timedelta(seconds=1)

@pytest.mark.asyncio
async def test_remove():
    user_id = "user123"
    session_id = "session123"

    await remove(user_id, session_id)

    # Assert that the session has been removed
    # You can modify this assertion based on your specific implementation
    assert await exists(user_id, session_id) is False

@pytest.mark.asyncio
async def test_retrieve_sessions_by_userid():
    user_id = "user123"

    sessions = await retrieve_sessions_by_userid(user_id)

    # Assert that the sessions dictionary is not empty
    assert sessions

    # Assert that the sessions dictionary contains the user_id
    assert user_id in sessions

    # Assert that the sessions for the user_id are sorted by last_active time in descending order
    # You can modify this assertion based on your specific implementation
    assert sessions[user_id] == sorted(sessions[user_id], key=lambda session: session.last_active, reverse=True)
