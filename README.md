# pteredor
A tool to help evaluate the teredo servers.

# Usage
Run use default teredo server list
```
python pteredor.py
```

or

```
>>> import pteredor
>>> pteredor.main()
```

Run append custom teredo server list
```
python pteredor.py server1 server2 ...
```

or

```
>>> server_list = [server1, server2 ...]
>>> pteredor.main(server_list)
```

Output
```
Stop teredo tunnel for run prober, Y/N? n
Starting probe NAT type...
The NAT type is cone.
Starting evaluate servers...
win10.ipv6.microsoft.com 65.55.158.118 211ms
win1711.ipv6.microsoft.com 157.56.144.215 242ms
teredo.iks-jena.de 217.17.192.217 283ms
teredo2.remlab.net 83.170.6.77 303ms
teredo-debian.remlab.net 83.170.6.76 312ms
teredo.trex.fi 195.140.195.140 410ms

The recommend server is 'win10.ipv6.microsoft.com'.
Do you want to set recommend teredo server, Y/N? n
```
