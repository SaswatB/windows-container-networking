# Windows CNI

## Overview
This repository contains plugins and tools for container networking in Windows:
* A [CNI plugin](https://github.com/containernetworking/cni/blob/master/SPEC.md) for Kubernetes and Mesos.

This is a fork of the [Azure CNI plugin] (https://github.com/Azure/azure-container-networking/) modified for Windows bare-metal installations. 

We welcome your feedback!


This project has adopted the [Microsoft Open Source Code of
Conduct](https://opensource.microsoft.com/codeofconduct/). For more information
see the [Code of Conduct
FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact
[opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional
questions or comments.

## Setup
1. Install GO
2. Clone this repo under your gopath
3. Install something that allows you to run make in windows e.g. [Make for Windows](http://gnuwin32.sourceforge.net/packages/make.htm)
``` 
cd $GOPATH
mkdir visualstudio.com
mkdir containernetworking
cd $GOPATH\visualstudio.com\containernetworking
```
## Build
```
make
out\wincni.exe
```
