import pytest
from datetime import datetime, timedelta
from app.auth.session import add, exists, update_last_activity, remove, retrieve_sessions_by_userid
from app.auth.schemas import SessionInfo

user_id = "user123"
session_id = "session123"

async def create_session_in_cache(
    user_id: str = "user123",
    session_id: str = "session123",
    ttl: int = 3600) -> bool:

    now = datetime.utcnow()
    exp = now + timedelta(seconds=ttl)
    # convert to seconds since the epoch
    exp = int(exp.timestamp())

    session_info_dict = {"user_id": user_id,
                         "session_id": session_id,
                         "user_agent": "Mozilla/5.0",
                         "user_host": "192.168.1.10",
                         "last_active": now, "exp": exp}

    value = SessionInfo(**session_info_dict)

    return await add(user_id, session_id, value, ttl)

@pytest.mark.asyncio
async def test_add():
    result = await create_session_in_cache(user_id=user_id, session_id=session_id)

    # expected result is True since we added the session
    assert result is True

@pytest.mark.asyncio
async def test_exists():
    result = await exists(user_id, session_id)

    # expected result is True since we added the session
    assert result is True

@pytest.mark.asyncio
async def test_update_last_activity():
    payload = {"sub": user_id, "sid": session_id}

    updated = await update_last_activity(payload)

    # expected result is True since we updated the session
    assert updated is True

@pytest.mark.asyncio
async def test_remove():
    result = await remove(user_id, session_id)

    # expected result is 1 since we only added 1 session
    assert result == 1

# @pytest.mark.asyncio
async def xtest_retrieve_sessions_by_userid():
    # Retrieve the sessions for the user_id
    sessions = await retrieve_sessions_by_userid(user_id)
    print(sessions)

    # Assert that the sessions dictionary is not empty
    assert sessions

    # Assert that the sessions dictionary contains the user_id
    assert user_id in sessions

    # Assert that the sessions for the user_id are sorted by last_active time in descending order
    # You can modify this assertion based on your specific implementation
    assert sessions[user_id] == sorted(sessions[user_id], key=lambda session: session.last_active, reverse=True)
