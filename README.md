# UnityProxyServer
A bug-fix version of Unity Proxy Server.

It's based on `gecko938`'s [bug-fix version](https://forum.unity3d.com/threads/networking-proxy-and-rpc-calls.136861/).

It can be compiled in Visual Studio 2017.

## Bug Fix

### By Ulysses:

* Argument parsing bug when specifying password.
* Show clear log when overlay ports are already in use. (Even a single port being occupied will cause the server refuse to run!)
* Make it compile-able on Visual Studio.

### By gecko938(MRB):

Sept. 26, 2012:

- Makefile: Build ProxyServer.cpp with no debug symbols by default as it may affect performance.

Sept. 18, 2012:

- RakPeer.cpp: Allow up to 256 (arbitrary higher number) server listen ports instead of just 32
- ProxyServer.cpp: Few more fixes: 1. Specifying a larger range of ports other than the default works now 2. Use array delete when deleting array 3. Allocate correct number of sockets for the number of ports requested (needed one more for the listen port)

Aug. 24, 2012:

- ProxyServer.cpp,h: Close proxy connections to clients when host of that port disconnects.

Aug. 22, 2012:

- ProxyServer.cpp: ProxyServer bug fixes: 1. Use the correct Receive function so we don't sometimes miss RPCs. 2. Immediately fetch next packet after processing packets from clients, so we don't slowly build more and more latency as unprocessed packets build up. 3. Deallocate client packets after they are processed.
