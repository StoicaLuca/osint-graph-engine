# OSINT Attribution Engine
# Copyright (c) 2026 Stoica Luca Ioan Michele. All rights reserved.
# Source-available for review only. Unauthorised use or redistribution
# is prohibited. See LICENSE.

import os
from neo4j import AsyncGraphDatabase
from dotenv import load_dotenv

# Load NEO4J_* values from .env into the process environment.
load_dotenv()


class GraphDB:
    """
    Manages the asynchronous connection pool to the Neo4j graph database.
    A single shared instance keeps the app from opening a new connection per request.
    """

    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "password")
        self._driver = None

    async def connect(self):
        """Initialises the connection pool. Lazy: no network call happens yet."""
        if not self._driver:
            self._driver = AsyncGraphDatabase.driver(
                self.uri, auth=(self.user, self.password)
            )
            print("Successfully initialized Neo4j async driver.")

    async def close(self):
        """Cleanly shuts down the connection pool."""
        if self._driver:
            await self._driver.close()
            self._driver = None
            print("Neo4j driver closed safely.")

    async def init_schema(self):
        """
        Creates uniqueness constraints so each entity exists as exactly one node.
        IF NOT EXISTS makes this safe to run on every startup.
        """
        constraints = [
            "CREATE CONSTRAINT domain_unique    IF NOT EXISTS FOR (d:Domain)    REQUIRE d.name    IS UNIQUE",
            "CREATE CONSTRAINT subdomain_unique IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.name    IS UNIQUE",
            "CREATE CONSTRAINT ip_unique        IF NOT EXISTS FOR (i:IPAddress) REQUIRE i.address IS UNIQUE",
            "CREATE CONSTRAINT username_unique  IF NOT EXISTS FOR (u:Username)  REQUIRE u.handle  IS UNIQUE",
            "CREATE CONSTRAINT platform_unique  IF NOT EXISTS FOR (p:Platform)  REQUIRE p.name    IS UNIQUE",
            "CREATE CONSTRAINT email_unique     IF NOT EXISTS FOR (e:Email)     REQUIRE e.address IS UNIQUE",
            "CREATE CONSTRAINT person_unique    IF NOT EXISTS FOR (pr:Person)   REQUIRE pr.name   IS UNIQUE",
        ]
        async with self._driver.session() as session:
            for constraint in constraints:
                await session.run(constraint)
        print("Neo4j schema constraints ensured.")

    async def execute_write(self, cypher_query: str, parameters: dict = None):
        """
        Runs a query that modifies the graph (MERGE / SET / CREATE).
        parameters defaults to None, not {}, because a mutable default would be
        shared across every call.
        """
        if parameters is None:
            parameters = {}
        if not self._driver:
            raise RuntimeError("Database driver not initialised — call connect() first.")

        async with self._driver.session() as session:
            result = await session.run(cypher_query, parameters)
            return await result.data()

    async def execute_read(self, cypher_query: str, parameters: dict = None):
        """Runs a read-only query (MATCH / RETURN) against the graph."""
        if parameters is None:
            parameters = {}
        if not self._driver:
            raise RuntimeError("Database driver not initialised — call connect() first.")

        async with self._driver.session() as session:
            result = await session.run(cypher_query, parameters)
            return await result.data()


# One shared instance for the whole application.
db = GraphDB()