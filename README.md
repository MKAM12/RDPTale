# RDPTale

is a simple script used to tell RDP Story in a target machine starting from all the network connection attempts, Authentication attempts, and then the post authentication sessions. to tell who gain successfull access to the target machine.
# Usage
Simply just specify the evtx logs' path then enjoy reading the story

```
.\RDPTale -AbsPath <Path to all evtx logs>
```

Note: it will export all logs in separate files to the same path.
