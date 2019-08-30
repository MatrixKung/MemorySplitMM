# libMSMM
## CURRENTLY UNDER DEVELOPMENT AND BARELY FUNCTIONAL, DO NOT EXPECT THIS TO WORK PROPERLY ANYTIME SOON
 A Manual mapping library with added protection against reverse engineering by splitting the target module up across the target process's memory. The primary use would be as an extra layer of DRM for your sensitive application.

## Use
 1. Include libMSMM's public header
```cpp
#include "libMSMM/include/libMSMM.h"
```
 2. Call libMSMM::MapImage
```cpp
 const bool did_map_succeed = libMSMM::MapImage(pRawDLLFile, RawDLLFileSize, pTargetApplicationName, libMSMM::MAP_ALL_OPTIONS);
```

## Restrictions
 >libMSMM does not support any form of exception handling within the module.
 
 >libMSMM requires modules to be built with static runtime due to issues importing dynamic runtime. Use compile options /MT or /MTd.
 
 >libMSMM does not support module exports
 
 >libMSMM does not support the library making use of functions that take a module base address for the module you load, and the base address passed into DLLMain is NULL.
 
 >libMSMM does not support module unloading, due to the nature of how the memory is laid out
 
 >libMSMM currently only supports x86 modules and x86 target applications, it is intended to add x64 support in the future

## Current Issues
 > Importing items from other modules can be inconsistant.
 
 > Loaded modules may cause crashes randomly due to exception handlers not being functional.

## Defining extra segments
 If you wish your module to be split into more segments within memory, you can use the C++ preprocessor to define code and data segments, as shown below - keep in mind PE restrictions on segment counts and [restricted segment names](https://docs.microsoft.com/en-us/cpp/build/reference/section-specify-section-attributes).
 
```cpp
#pragma code_seg(".cd_seg")
#pragma data_seg(".da_seg")
#pragma bss_seg(".bs_seg")
#pragma const_seg(".cs_seg")
``` 

## Debugging
 debugging code mapped with libMSMM is very difficult due to the fact the data is spread across memory and normal tools will not link debug libraries to the code. It is recommended all testing and development be done with standard loadlibrary mapping and then releases use libMSMM for protection of code.
 
 libMSMM makes use of extensive logging using the spdlog library so you can keep track of what is going on under the hood. Compile in debug mode to see this output. libMSMM Release will log Warnings and Errors to stdout

## Dependancies
 [capstone](http://www.capstone-engine.org/) for resolving reletive JUMP/CALL operations.
 
 [spdlog](https://github.com/gabime/spdlog) for logging

# MSMM
 An example implemtation of libMSMM.
 
 Can be used as a manual map injector with the following paramaters.
```MSMM.exe <target dll path> <target application name>```

# Disclaimer
 I do not claim responsablity for the use/distribution of this applicaiton.
 
 This is not intended for use in malware or any other activity which may be malicious, that would be called a 'dick move' and you should feel bad for even thinking about using it to make your malware harder to detect.
 
# Other
 If you find a proper use for this, please give credit and let me know! I would be very interested in how this method may be utilised.
