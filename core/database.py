import os
from neo4j import AsyncGraphDatabase
from dotenv import load_dotenv

# Load environment variables from the .env file into the operating system's memory
load_dotenv()

class GraphDB:
    """
    Manages the asynchronous connection pool to the Neo4j Graph Database.
    Implemented as a Singleton-like structure to ensure we don't open 
    thousands of database connections simultaneously.
    """
    
    def __init__(self):
        # Fetch the credentials securely from the environment variables
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "password")
        
        # The driver is the actual engine that maintains the connection pool
        self._driver = None

    async def connect(self):
        """Initializes the connection pool to Neo4j."""
        if not self._driver:
            self._driver = AsyncGraphDatabase.driver(
                self.uri, 
                auth=(self.user, self.password)
            )
            print("Successfully initialized Neo4j async driver.")

    async def close(self):
        """Cleanly shuts down the connection pool."""
        if self._driver:
            await self._driver.close()
            print("Neo4j driver closed safely.")

    async def execute_write(self, cypher_query: str, parameters: dict = None):
        """
        Executes a write transaction (INSERT/UPDATE) to the graph.
        We use an async session and the 'with' context manager to ensure
        the network socket to the database is released immediately after.
        """
        if parameters is None:
            parameters = {}
            
        # Using the context manager we learned about!
        async with self._driver.session() as session:
            # We wrap the actual database call in a transaction to prevent data corruption
            result = await session.run(cypher_query, parameters)
            return await result.data()

# We instantiate a single global instance of our database manager
db = GraphDB()