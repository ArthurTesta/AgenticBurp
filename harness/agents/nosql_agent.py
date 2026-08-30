from .base_agent import BaseAgent


class NosqlAgent(BaseAgent):
    """Agent for detecting NoSQL injection vulnerabilities."""
    name = "nosql"

    @property
    def specialty_prompt(self) -> str:
        return """
NoSQL injection vulnerabilities. Look for:

REQUEST INDICATORS:
- JSON request bodies (Content-Type: application/json)
- API endpoints (REST, GraphQL)
- MongoDB-style queries in request parameters
- NoSQL database error messages in responses
- Endpoints with /api/, /rest/, /graphql in path

NOSQL OPERATORS IN INPUT:
- MongoDB operators: $ne, $gt, $lt, $gte, $lte, $in, $nin, $regex, $where
- Logical operators: $and, $or, $not, $nor
- Array operators: $all, $elemMatch, $size
- Update operators: $set, $unset, $inc, $push, $pull
- Projection operators: $slice, $meta

INJECTION PATTERNS:
- JSON injection: {"username": {"$ne": ""}}
- Boolean-based: {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
- Time-based: {"username": {"$where": "sleep(5000)"}}
- Regex-based: {"username": {"$regex": ".*"}}
- Type confusion: {"username": {"$gt": ""}}
- Array injection: {"username": ["admin", "user"]}

RESPONSE INDICATORS:
- NoSQL database error messages (MongoDB, CouchDB, etc.)
- Different responses based on NoSQL operator injection
- Time delays indicating injection success
- Unexpected data in responses (data exfiltration)
- Error 500 with NoSQL-related stack traces

DATABASE-SPECIFIC SIGNALS:
- MongoDB: "MongoError", "SyntaxError", "BSON"
- CouchDB: "CouchDB", "MapReduce"
- Redis: "Redis", "eval"
- Cassandra: "Cassandra", "CQL"
- Elasticsearch: "Elasticsearch", "query"

For suggested_test, propose:
- Boolean-based NoSQLi: {"username": {"$ne": ""}, "password": {"$ne": ""}}
- Time-based NoSQLi: {"username": {"$where": "sleep(5000)"}}
- Data exfiltration: {"username": {"$regex": ".*"}, "password": {"$ne": ""}}
- Type confusion: {"username": {"$gt": ""}}

suggested_test MUST be concrete JSON payloads that can be sent via Burp Repeater:
- '{"username": {"$ne": ""}, "password": {"$ne": ""}}'
- '{"username": {"$where": "sleep(5000)"}}'
- '{"username": {"$regex": ".*"}}'

CONTEXT MATTERS:
- NoSQL injection often doesn't use quotes or SQL syntax
- JSON syntax must be valid (proper braces, quotes, commas)
- Operators are database-specific (MongoDB uses $ operators)
- NoSQLi can bypass authentication even when SQLi cannot
- Time-based NoSQLi requires server-side JavaScript evaluation
"""
