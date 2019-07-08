# Project list

The most trivial tool to list all nginx enabled sites in a server and which status 
code those respond with over https.

Usage:
`prolist username ssh_key_path server_name`

Example output:
```
project1: project1.company.eu -> 404
project2: project2.kontor.ee -> 200
```

Disclaimer: written as go language practice, not best for production usage.