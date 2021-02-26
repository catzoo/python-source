# python source
This sends a query to a valve server. For more information, visit [here](https://developer.valvesoftware.com/wiki/Server_queries "Server Queries")

I took the idea from [this](https://github.com/frostschutz/SourceLib/blob/master/SourceQuery.py) code.

Import `query.py` to use this code.

## Examples:
```python
from query import Query

query = Query("127.0.0.1", "27015")
data = query.info()
```

Look at query.py for more docmentation.
