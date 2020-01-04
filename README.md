# pteredor
A tool to help evaluate the teredo servers.

# Compatible
Tested with Python 2.7 and above.

# Notice
Ensure DNS resolve and firewall setting is correct.

# Usage
Run use default teredo server list.
```
python pteredor.py -h -p 54301

pteredor [-p <port>] [-P <port>] [-h] [<server1> [<server2> [...]]]
      -p  Set the local port num. (client)
      -P  Set the remote port num. (server)
      -h  Show this help.

          The teredo server is a host name (domain or IP).
```

or

```
>>> import pteredor
>>> pteredor.main(local_port=256, remote_port=3544)
```

Run append custom teredo server list.
```
python pteredor.py server1 server2 ...
```

or

```
>>> pteredor.main(server1, server2 ...)
```

or

```
>>> server_list = [server1, server2 ...]
>>> pteredor.main(server_list)
```

Output
```
Stop teredo tunnel for run prober, Y/N? n
try bind local port: 2694
Starting probe NAT type...
The NAT type is cone.
Starting evaluate servers...
65.55.158.118 ['win10.ipv6.microsoft.com', 'win1710.ipv6.microsoft.com'] 202ms
157.56.144.215 ['win1711.ipv6.microsoft.com'] 242ms
83.170.6.76 ['teredo.remlab.net', 'teredo-debian.remlab.net'] 312ms
217.17.192.217 ['teredo.iks-jena.de'] 327ms
195.140.195.140 ['teredo.trex.fi'] 374ms

The recommend server is ['win10.ipv6.microsoft.com', 'win1710.ipv6.microsoft.com'].
Do you want to set recommend teredo server, Y/N? n
Press enter to over...
```
