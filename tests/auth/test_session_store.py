import pytest
import uuid
import asyncio
import random
from typing import Optional
from datetime import datetime, timedelta
from app.auth import session_store
from app.auth.schemas import SessionInfo

user_id = "user-" + str(uuid.uuid4())[5:]
session_id = "session-" + str(uuid.uuid4())[8:]

async def create_session_in_cache(
    user_id: str,
    session_id: Optional[str] = None,
    ttl: int = 3600) -> bool:
    """
    Create a new session in the cache.

    This function creates a new session with the given user ID and session ID,
    and adds it to the cache. The session has a time-to-live (TTL) specified by
    the ttl parameter.

    Args:
        user_id (str): The ID of the user.
        session_id (str): The ID of the session.
        ttl (int, optional): The TTL of the session in seconds. Defaults to 3600.

    Returns:
        bool: True if the session was successfully added to the cache, False otherwise.
    """
    if session_id is None:
        session_id = "session-" + str(uuid.uuid4())[8:]

    # Get the current time
    now = datetime.utcnow()

    # Calculate the expiration time by adding the TTL to the current time
    exp = now + timedelta(seconds=ttl)

    # Convert the expiration time to seconds since the epoch
    exp = int(exp.timestamp())

    # generate random number from 10 to 20
    ip_addr = "192.168.1." + str(random.randint(10, 20))

    # Create a new session info dictionary
    session_info_dict = {
        "user_id": user_id,
        "session_id": session_id,
        "user_agent": "Mozilla/5.0",
        "user_host": ip_addr,
        "last_active": now,
        "exp": exp
    }

    # Create a new SessionInfo object from the dictionary
    value = SessionInfo(**session_info_dict)

    # Add the session to the cache and return the result
    return await session_store.add(user_id, session_id, value, ttl)

@pytest.mark.asyncio
async def test_add():
    """
    Test the add function.

    This test checks if a session can be successfully added to the cache.
    The expected result is True since we are adding the session.
    """
    # Call the function with a user_id and session_id
    result = await create_session_in_cache(user_id=user_id, session_id=session_id)

    # expected result is True since we added the session
    assert result is True

@pytest.mark.asyncio
async def test_exists():
    """
    Test the exists function.

    This test checks if a session exists in the cache.
    The expected result is True since we added the session in the previous test.
    """
    # Call the function with a user_id and session_id
    result = await session_store.exists(user_id, session_id)

    # Assert that the result is True, indicating the session exists
    assert result is True

@pytest.mark.asyncio
async def test_expiration():
    """
    Test session expiration.

    This test checks if a session expires after the specified time-to-live (TTL).
    The expected result is False since the session should have expired.
    """
    # Generate a new session ID for testing
    test_session_id = "session-" + str(uuid.uuid4())[8:]

    # Create a new session with a TTL of 3 seconds
    await create_session_in_cache(user_id, test_session_id, ttl=3)

    # check is the session exists
    result = await session_store.exists(user_id, test_session_id)
    # Assert that the result is True, indicating the session exists
    assert result is True

    # Wait 2s
    await asyncio.sleep(2)
    # check is the session exists
    result = await session_store.exists(user_id, test_session_id)
    # Assert that the result is True, indicating the session still exists
    assert result is True

    # Wait for the session to expire
    await asyncio.sleep(1)
    # check is the session exists
    result = await session_store.exists(user_id, test_session_id)
    # Assert that the result is False, indicating the session has expired
    assert result is False

@pytest.mark.asyncio
async def test_update_last_activity():
    """
    Test the update_last_activity function.

    This test checks if the last activity of a session can be successfully updated.
    If the session does not exist, it creates a new session.
    The expected result is True since we are updating the session.
    """
    # Check if the session exists, if not create a new session
    if not await session_store.exists(user_id, session_id):
        print("Session not exists, creating session in cache...")
        await create_session_in_cache(user_id=user_id, session_id=session_id)

    # Create a valid token payload
    token_payload = {"sub": user_id, "sid": session_id}

    # update existing session last activity
    result = await session_store.update_last_activity(token_payload)

    # Assert that the result is True, indicating the session was successfully updated
    assert result is True

    # Create a invalid token payload (fake session id)
    token_payload = {"sub": user_id, "sid": "session-" + str(uuid.uuid4())[8:]}

    # update non-existing session last activity
    result = await session_store.update_last_activity(token_payload)

    # Assert that the result is False, indicating the session was not updated
    assert result is False

@pytest.mark.asyncio
async def test_remove():
    """
    Test the remove function.

    This test checks if a session can be successfully removed from the cache.
    The expected result is 1 since we are removing one session.
    """
    # Call the function with a user_id and session_id
    result = await session_store.remove(user_id, session_id)

    # Assert that the result is 1, indicating one session was successfully removed
    assert result == 1

    # expect raise ValueError because no user_id is provided
    with pytest.raises(ValueError):
        await session_store.remove("", session_id)

@pytest.mark.asyncio
async def test_remove_all_user_sessions():
    """
    Test the functionality of removing all user sessions.

    This test function first creates two sessions for a user in the cache.
    Then it calls the remove function to delete all sessions of the user.
    The result should be greater than 1, indicating that more than one session was removed.

    Raises:
        AssertionError: If the result is not greater than 1, the test will fail.
    """
    # Create two sessions for the user in the cache
    await create_session_in_cache(user_id)
    await create_session_in_cache(user_id)

    # Call the remove function to delete all sessions of the user
    result = await session_store.remove(user_id)

    # Assert that the result is greater than 2, indicating that more than one session was removed
    assert result >= 2

@pytest.mark.asyncio
async def test_retrieve_by_userid():
    """
    Test the retrieve_by_userid function.

    This test checks if the sessions for a user can be successfully retrieved from the cache.
    It first ensures two sessions exist for the user, then retrieves the sessions and checks
    the results.
    """
    # Generate a second session ID for testing
    session_id2 = "session-" + str(uuid.uuid4())[8:]

    # Check if the sessions exist, if not create new sessions
    if not await session_store.exists(user_id, session_id):
        print("Session not exists, creating 2 sessions in cache...")
        await create_session_in_cache(user_id=user_id, session_id=session_id)
        await create_session_in_cache(user_id=user_id, session_id=session_id2)

    # Call the function with the user_id
    sessions = await session_store.retrieve_by_userid(user_id)

    # Assert that the sessions dictionary is not empty
    assert sessions
    # print(sessions)

    # Assert that the sessions dictionary contains the user_id
    assert user_id in sessions

    # Assert that the sessions dictionary contains 2 sessions for the user_id
    assert len(sessions[user_id]) == 2

    # Iterate over the sessions and assert that the session IDs exist
    for session in sessions[user_id]:
        assert session.session_id in [session_id, session_id2]

@pytest.mark.asyncio
async def test_retrieve():
    """
    Test the retrieve function.

    This test checks if a session can be successfully retrieved from the cache.
    It first ensures the session exists, then retrieves the session and checks the result.
    """
    # Check if the session exists, if not create a new session
    if not await session_store.exists(user_id, session_id):
        print("Session not exists, creating session in cache...")
        await create_session_in_cache(user_id=user_id, session_id=session_id)

    # Call the function with the user_id and session_id
    session = await session_store.retrieve(user_id, session_id)
    # print(session)

    # Assert that the session is not None
    assert session

    # Assert that the session contains the correct user_id
    assert session.user_id == user_id

    # Assert that the session contains the correct session_id
    assert session.session_id == session_id

@pytest.mark.asyncio
async def test_update1():
    """
    Test the update function.

    This test checks if a session can be successfully updated in the cache.
    It first ensures the session exists, then updates the session and checks the result.
    """
    # Check if the session exists, if not create a new session
    if not await session_store.exists(user_id, session_id):
        print("Session not exists, creating session in cache...")
        await create_session_in_cache(user_id=user_id, session_id=session_id)

    # Generate a new user agent for testing
    new_user_agent = "Edge/12.0.0"

    # Retrieve the session from the cache
    session: SessionInfo = await session_store.retrieve(user_id, session_id)

    # Update the user agent
    session.user_agent = new_user_agent

    # Update the session in the cache
    result = await session_store.update(user_id, session_id, session, 5)

    # Assert that the result is True, indicating the session was successfully updated
    assert result is True

    # Retrieve the session from the cache
    session: SessionInfo = await session_store.retrieve(user_id, session_id)

    # Assert that the user agent has been updated
    assert session.user_agent == new_user_agent

    # Wait for the session to expire
    await asyncio.sleep(5)
    result = await session_store.exists(user_id, session_id)
    # Assert that the result is False, indicating the session has expired
    assert result is False

@pytest.mark.asyncio
async def test_update2():
    """
    Test the update function.

    This test checks if a session can be successfully updated in the cache.
    It first ensures the session exists, then updates the session and checks the result.
    """
    # Check if the session exists, if not create a new session
    if not await session_store.exists(user_id, session_id):
        print("Session not exists, creating session in cache...")
        await create_session_in_cache(user_id=user_id, session_id=session_id)

    # Generate a new user agent for testing
    new_user_agent = "Mars/12.0.0"

    # Retrieve the session from the cache
    session: SessionInfo = await session_store.retrieve(user_id, session_id)

    # Update the user agent
    session.user_agent = new_user_agent

    # Update the session in the cache
    result = await session_store.update(user_id, session_id, session)

    # Assert that the result is True, indicating the session was successfully updated
    assert result is True

    # Retrieve the session from the cache
    session: SessionInfo = await session_store.retrieve(user_id, session_id)

    # Assert that the user agent has been updated
    assert session.user_agent == new_user_agent

@pytest.mark.asyncio
async def test_update_ttl():
    """
    Test the update_ttl function.

    This test checks if the time-to-live (TTL) of a session can be successfully updated in the cache.
    It first ensures the session exists, then updates the TTL of the session and checks the result.
    """
    # Check if the session exists, if not create a new session
    if not await session_store.exists(user_id, session_id):
        print("Session not exists, creating session in cache...")
        await create_session_in_cache(user_id=user_id, session_id=session_id)

    # Update the TTL of the session
    result = await session_store.update_ttl(user_id, session_id, 5)

    # Assert that the result is True, indicating the TTL was successfully updated
    assert result is True

    # Wait 4s
    await asyncio.sleep(4)
    # check is the session exists
    result = await session_store.exists(user_id, session_id)
    # Assert that the result is True, indicating the session still exists
    assert result is True

    # Wait for the session to expire
    await asyncio.sleep(1)
    result = await session_store.exists(user_id, session_id)
    # Assert that the result is False, indicating the session has expired
    assert result is False