# chocoProxy

chocoProxy is a Windows tool intended to aid in reverse engineering Windows applications' network traffic. The proxy works by hooking the sending and receiving Windows APIs after being injected into a target process. The traffic can be modified to arbitrary values to observe the behaviour of an application when provided with unexpected input. The tool is meant to expedite the discovery and development of memory corruption exploits that occur in the implementation of complex and custom network protocols. chocoProxy takes away the necessity for exploit developers to reverse engineer a network protocol by utilizing the existing client/server functionality in the target.

# Requirements

You need the following tools installed on a Windows 10 machine:
  - Python 3.6+ 64bit
  - .Net 4.7.1

# Documentation

See the Wiki.
