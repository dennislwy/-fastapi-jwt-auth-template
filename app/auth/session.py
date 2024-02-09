from typing import Dict, List, Optional
from datetime import datetime
from aiocache import SimpleMemoryCache
from .schemas import SessionInfo

cache = SimpleMemoryCache() # key: session_id, namespace: user_id, value: SessionInfo

async def add(user_id: str, session_id: str, value, ttl: int) -> bool:
    """
    Add a session to the cache.

    Args:
        user_id (str): The ID of the user.
        session_id (str): The ID of the session.
        value (Any): The value object.
        ttl (int): The time-to-live (TTL) for the session in seconds.

    Returns:
        bool: True if the session was successfully added to the cache, False otherwise.
    """
    return await cache.add(key=session_id, value=value, namespace=user_id, ttl=ttl)

async def exists(user_id: str, session_id: str) -> bool:
    """
    Checks if a session exists in the cache.

    Args:
        user_id (str): The ID of the user.
        session_id (str): The ID of the session.

    Returns:
        bool: True if the session exists, False otherwise.
    """
    return await cache.exists(key=session_id, namespace=user_id)

async def update_last_activity(payload: dict):
    """
    Update the last activity timestamp of the user session.

    Args:
        payload (dict): The payload of the token.

    """
    # Retrieve the user ID & session ID from the payload
    user_id = payload.get("sub")
    session_id = payload.get("sid")

    if not await cache.exists(key=session_id, namespace=user_id):
        return

    # get session info from cache
    value: SessionInfo = await cache.get(key=session_id, namespace=user_id)
    value.last_active = datetime.utcnow()
    await cache.set(key=session_id, namespace=user_id, value=value)

async def remove(user_id: Optional[str] = None, session_id: Optional[str] = None):
    """
    Remove sessions based on the provided user_id and session_id.

    Args:
        user_id (Optional[str]): The ID of the user. If provided, sessions associated with this user will be removed.
        session_id (Optional[str]): The ID of the session. If provided, the specified session will be removed.

    Returns:
        None
    """
    if user_id:
        if session_id:
            # delete the specified session for the user
            await cache.delete(key=session_id, namespace=user_id)

        else:
            # delete all sessions for the user
            sessions = await retrieve_sessions_by_userid(user_id=user_id, sort=False)
            for session in sessions[user_id]:
                await cache.delete(key=session.session_id, namespace=user_id)

    else:
        if session_id is None:
            # delete all sessions
            await cache.clear()
        else:
            raise ValueError("session_id must be provided if user_id is not provided")

async def retrieve_sessions_by_userid(user_id: Optional[str] = None, sort: bool = True) -> Dict[str, List[SessionInfo]]:
    """
    Gets session(s) from the cache, grouped by user id.

    Args:
        user_id (Optional[str]): The ID of the user. If None, all sessions will be returned.
        sort (bool): Whether or not to sort the sessions by last active time in descending order.

    Returns:
        Dict[str, List[SessionInfo]]: A dictionary of sessions, grouped by user ID.
    """
    c = cache._cache

    sessions = {} # key: user_id, value: list of SessionInfo

    for key, value in c.items():
        if user_id is None or key.startswith(user_id):
            user_id = key[:36]
            if user_id not in sessions:
                sessions[user_id] = []
            sessions[user_id].append(value)

    if sort:
        for user_id in sessions:
            sessions[user_id] = sorted(sessions[user_id],
                                       key=lambda session: session.last_active, reverse=True)

    return sessions