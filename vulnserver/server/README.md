# Vulnerable chat server (vchat)

Our vulnerable chat server (vchat) is based on [vulnserver](http://thegreycorner.com/vulnserver.html). Here are the major changes
- Added the chat server functionality. The chat server receives messages from clients. Each message is forwarded to all other clients.
- CTRL+C to exit the server gracefully

How to perform chat via vchat.

[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/fIcf5A0CCHU/0.jpg)](https://youtu.be/fIcf5A0CCHU)

## QuickEdit Mode and Copy and Paste in CMD

We have to disable the [QuickEdit Mode](https://stackoverflow.com/questions/48192465/accept-blocks-with-pending-connections-ctrlc-unblocks) and actually the Mark and Copy functionality of the Windows console too. Otherwise, the text selection mode halts the running program, e.g., our chat server. Ctrl+C can cancel the mode. However, it is really annoying. We now disable the QuickEdit Mode in the code. 

The *Mark* and *Copy* functionality of the console can still cause trouble if they are used by people.


## To-Do
1. Change the console program to a WIndows application? We then will not have the *Mark* and *Copy* issue.
