# python source
This sends a query to a valve server (such as Garry's Mod and TF2)
I took the idea from [this](https://github.com/frostschutz/SourceLib/blob/master/SourceQuery.py) code.

## Examples:
Import `query.py` to use this code.

```python
from query import Query

query = Query("127.0.0.1", "27015")
data = query.info()
```

Look at query.py for more usage and documentation
For more information about querying valve servers, visit [here](https://developer.valvesoftware.com/wiki/Server_queries "Server Queries")
