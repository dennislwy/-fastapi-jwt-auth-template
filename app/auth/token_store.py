"""
This module provides functions for active token store.
"""
from typing import Optional
from aiocache import SimpleMemoryCache

# Use memory cache to store active tokens
# key: {token_id}
# value: sibling_token_id
cache = SimpleMemoryCache()

async def add(token_id: str, sibling_token_id: str, ttl: int) -> bool:
    """
    Add a token to the cache store.

    Args:
        token_id (str): The ID of the token.
        sibling_token_id (str): The ID of the sibling token (access or refresh token).
        ttl (int): The time-to-live (TTL) for the token in seconds.

    Returns:
        bool: True if the token was successfully added to the store, False otherwise.
    """
    print(f"Adding token '{token_id}' to store, value '{sibling_token_id}'")
    return await cache.add(key=token_id, value=sibling_token_id, ttl=ttl)


async def exists(token_id: str) -> bool:
    """
    Checks if a token exists in the cache store.

    Args:
        token_id (str): The ID of the token.

    Returns:
        bool: True if the token exists, False otherwise.
    """
    return await cache.exists(key=token_id)

async def retrieve(token_id: str) -> Optional[str]:
    """
    Retrieve a token from the cache store.

    Args:
        token_id (str): The ID of the token.

    Returns:
        Optional[str]: The ID of the sibling token if it exists, None otherwise.
    """
    return await cache.get(key=token_id)


async def remove(token_id: str) -> bool:
    """
    Remove a token from the cache store.

    Args:
        token_id (str): The ID of the token.

    Returns:
        bool: True if the token was successfully removed from the store, False otherwise.
    """
    print(f"Removing token '{token_id}' from token store")
    return await cache.delete(key=token_id)
