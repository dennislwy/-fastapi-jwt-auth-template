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

SESSION_NOT_EXISTS_MESSAGE = "Session not exists, creating session in cache..."

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
    Test the add function to ensure that a session is added to the cache successfully.

    Steps:
    1. Call the 'create_session_in_cache' function with a user_id and session_id.
    2. Retrieve the result of the function call.
    3. Assert that the result is True, indicating that the session was added successfully.
    """
    # Call the function with a user_id and session_id
    result = await create_session_in_cache(user_id=user_id, session_id=session_id)

    # expected result is True since we added the session
    assert result is True

@pytest.mark.asyncio
async def test_exists():
    """
    Test the existence of a session in the session store.

    Purpose:
    - This test verifies that the `exists` function of the session store correctly determines
    whether a session exists.

    Steps:
    1. Call the `exists` function of the session store with a user_id and session_id.
    2. Assert that the result is True, indicating that the session exists.
    """
    # Call the function with a user_id and session_id
    result = await session_store.exists(user_id, session_id)

    # Assert that the result is True, indicating the session exists
    assert result is True

@pytest.mark.asyncio
async def test_expiration():
    """
    Test the expiration of a session in the session store.

    Purpose:
    - To verify that a session in the session store expires after a certain time.

    Steps:
    1. Generate a new session ID for testing.
    2. Create a new session with a TTL of 3 seconds.
    3. Check if the session exists in the session store. Assert that the result is True.
    4. Wait for 2 seconds.
    5. Check if the session still exists in the session store. Assert that the result is True.
    6. Wait for the session to expire.
    7. Check if the session exists in the session store. Assert that the result is False.
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
async def test_remove():
    """
    Test the remove function of the session store.

    Purpose:
    - To verify that the remove function removes a session from the session store.

    Steps:
    1. Call the remove function with a user_id and session_id.
    2. Assert that the result is 1, indicating that one session was successfully removed.
    3. Expect a ValueError to be raised when calling the remove function with an empty user_id.
    """

    # Call the function with a user_id and session_id
    result = await session_store.remove(user_id, session_id)

    # Assert that the result is 1, indicating one session was successfully removed
    assert result == 1

    # Expect raise ValueError because no user_id is provided
    with pytest.raises(ValueError):
        await session_store.remove("", session_id)

@pytest.mark.asyncio
async def test_remove_all_user_sessions():
    """
    Test the functionality of removing all sessions of a user from the session store.

    Steps:
    1. Create two sessions for the user in the cache.
    2. Call the remove function to delete all sessions of the user.
    3. Assert that the result is greater than or equal to 2, indicating that more
    than one session was removed.
    """
    # Create two sessions for the user in the cache
    await create_session_in_cache(user_id)
    await create_session_in_cache(user_id)

    # Call the remove function to delete all sessions of the user
    result = await session_store.remove(user_id)

    # Assert that the result is greater than or equal to 2, indicating that more than
    # one session was removed
    assert result >= 2

@pytest.mark.asyncio
async def test_retrieve_by_userid():
    """
    Test the retrieve_by_userid function of the session store.

    Purpose:
    - This test verifies that the retrieve_by_userid function returns the correct sessions
    for a given user ID.

    Steps:
    1. Generate a second session ID for testing.
    2. Check if the sessions exist for the user ID, and create new sessions if they don't exist.
    3. Call the retrieve_by_userid function with the user ID.
    4. Assert that the sessions dictionary is not empty.
    5. Assert that the sessions dictionary contains the user ID.
    6. Assert that the sessions dictionary contains 2 sessions for the user ID.
    7. Iterate over the sessions and assert that the session IDs exist.
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
    Test the retrieve function of the session store.

    Purpose:
    - To verify that the retrieve function returns the correct session object.

    Steps:
    1. Check if the session exists for the given user_id and session_id.
    2. If the session does not exist, create a new session in the cache.
    3. Call the retrieve function with the user_id and session_id.
    4. Assert that the retrieved session is not None.
    5. Assert that the retrieved session has the correct user_id.
    6. Assert that the retrieved session has the correct session_id.
    """
    # Check if the session exists, if not create a new session
    if not await session_store.exists(user_id, session_id):
        print(SESSION_NOT_EXISTS_MESSAGE)
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
async def test_update_data():
    """
    Test the update functionality of the session store.

    Purpose:
    - To verify that the session can be successfully updated in the cache.

    Steps:
    1. Check if the session exists in the cache.
    2. If the session does not exist, create a new session in the cache.
    3. Generate new data to update the session.
    4. Update the session in the cache with the new data.
    5. Assert that the update operation returns True, indicating a successful update.
    6. Retrieve the session from the cache.
    7. Assert that the user agent in the retrieved session matches the updated user agent.
    """

    # Check if the session exists, if not create a new session
    if not await session_store.exists(user_id, session_id):
        print(SESSION_NOT_EXISTS_MESSAGE)
        await create_session_in_cache(user_id=user_id, session_id=session_id)

    # Generate a new data to update
    new_user_agent = "MyUserAgent/2.0.0"
    data = {"user_agent": new_user_agent}

    # Update the session in the cache
    result = await session_store.update(user_id=user_id,
                                        session_id=session_id,
                                        data=data)

    # Assert that the result is True, indicating the session was successfully updated
    assert result is True

    # Retrieve the session from the cache
    session: SessionInfo = await session_store.retrieve(user_id, session_id)

    # Assert that the user agent has been updated
    assert session.user_agent == new_user_agent

@pytest.mark.asyncio
async def test_update_data_and_ttl():
    """
    Test the update of session data and TTL (Time To Live) in the session store.

    Purpose:
    - To verify that the session data can be successfully updated in the session store.
    - To verify that the TTL of the session is working as expected.

    Steps:
    1. Check if the session exists in the session store.
    2. If the session does not exist, create a new session.
    3. Generate new data to update the session.
    4. Update the session in the session store with a TTL of 5 seconds.
    5. Assert that the session update was successful.
    6. Retrieve the session from the session store.
    7. Assert that the user agent in the session has been updated.
    8. Wait for 4 seconds.
    9. Check if the session still exists in the session store.
    10. Assert that the session still exists.
    11. Wait for the session to expire.
    12. Check if the session still exists in the session store.
    13. Assert that the session has expired.
    """

    # Check if the session exists, if not create a new session
    if not await session_store.exists(user_id, session_id):
        print(SESSION_NOT_EXISTS_MESSAGE)
        await create_session_in_cache(user_id=user_id, session_id=session_id)

    # Generate a new data to update
    new_user_agent = "MyUserAgent/1.0.0"
    data = {"user_agent": new_user_agent}

    # Update the session in the cache with TTL 5 seconds
    result = await session_store.update(user_id=user_id,
                                        session_id=session_id,
                                        data=data,
                                        ttl=5)

    # Assert that the result is True, indicating the session was successfully updated
    assert result is True

    # Retrieve the session from the cache
    session_info: SessionInfo = await session_store.retrieve(user_id, session_id)

    # Assert that the user agent has been updated
    assert session_info.user_agent == new_user_agent

    # Wait 4 seconds
    await asyncio.sleep(4)

    # Check if the session still exists in the cache
    exists = await session_store.exists(user_id, session_id)

    # Assert that the session still exists
    assert exists is True

    # Wait for the session to expire
    await asyncio.sleep(1)

    # Check if the session still exists in the cache
    result = await session_store.exists(user_id, session_id)

    # Assert that the result is False, indicating the session has expired
    assert result is False

@pytest.mark.asyncio
async def test_update_ttl():
    """
    Test the update_ttl function of the session store.

    Purpose:
    - To verify that the TTL (Time To Live) of a session can be successfully updated.

    Steps:
    1. Check if the session exists. If not, create a new session.
    2. Update the TTL of the session to 5 seconds.
    3. Assert that the update operation was successful.
    4. Wait for 4 seconds.
    5. Check if the session still exists.
    6. Assert that the session still exists.
    7. Wait for the session to expire (1 second).
    8. Check if the session still exists.
    9. Assert that the session has expired.
    """
    # Check if the session exists, if not create a new session
    if not await session_store.exists(user_id, session_id):
        print(SESSION_NOT_EXISTS_MESSAGE)
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


@pytest.mark.asyncio
async def test_update_non_exist_session():
    """
    Test the update function of the session store when the session does not exist.

    Steps:
    1. Generate a new user agent to update the session.
    2. Create a data dictionary with the new user agent.
    3. Call the update method of the session store with a non-existent session ID.
    4. Assert that the result is False, indicating that the session was not updated.
    """
    # Generate a new data to update
    new_user_agent = "MyUserAgent/2.0.0"
    data = {"user_agent": new_user_agent}

    # Update the session in the cache
    result = await session_store.update(user_id=user_id,
                                        session_id="non-exist-session-id",
                                        data=data)

    # Assert that the result is False, indicating the session was not updated
    assert result is False
