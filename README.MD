# README.MD for running MyPinTool.cpp
## Required:
* Intel's Pin Tool `pin-3.2-81205-gcc-linux`  
* `gcc`
* `g++`
## 
Will not work in latest Ubuntu distributions, downgrade your kernel to 4.8.x.  
This tool will not work in latest PIN tool as well, due to changes to the  
paths and dependencies. However it will work flawlessly in the above mentioned   
version of pin tool.  
## Installation
Unzip the files and move `MyPinTool.cpp`, `makefile`, `makefile.rules`
to `MyPinTool` folder in your `pin/source/tools` location.
Replace old files with these new ones.
On the terminal use following commands :
```
$: make clean
$: path\to\pin -t path\to\MyPinTool.so -- /bin/<application>
```
##
The output for each lab task is produced in different files named  
* soln-1.out
* soln-2.out
* soln-3.out
* soln-4.out
* soln-5.out
* 1soln-6.out
## Author

* **Ashwin Joshi** - [Ashwin1421](https://github.com/Ashwin1421)
