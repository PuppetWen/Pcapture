# Pcapture
基于hook的改包工具
<br>
声明: 工具仅供安全研究或授权渗透，非法用途后果自负。<br>

### 功能介绍
基于r0capture实现的抓包改包工具
* 目的：有些app对vpn等代理方式检测，逆向分析对于渗透测试的短流程来说太繁琐？想着做一个功能用于渗透测试中修改包方便
![image](https://user-images.githubusercontent.com/121593186/211701402-7e050365-ba7f-4ab4-9d85-a23cd1231acf.png)

* `1分区暂时除clear功能外为实现其他功能`
* `2分区为拦截Send数据使用`
* `3分区为拦截Recv数据使用`

### 使用方式
* 安装所需要的库(会改变frida版本)  
```pip install -r requirements.txt```  
* 启动手机端frida-server，在命令行中输入类似以下命令，点击start  
```Pcapture -U -P [process name]  -v -p test.pcap```  
* 以下为我改包截图  
![image](https://user-images.githubusercontent.com/121593186/211702658-3e737e3d-fc89-4821-a269-0d2f180cdc02.png)
![image](https://user-images.githubusercontent.com/121593186/211705182-b603e918-09e6-4ab5-b19e-5989ce28b698.png)
![image](https://user-images.githubusercontent.com/121593186/211705361-8ddee28d-6434-4177-949f-67f85982f0d1.png)
* 详细使用命令参照以下  
```Usage: Pcapture [-pcap <path>] [-host <192.168.1.1:27042>] [-verbose] [-ssl <lib>] [--isUsb] [--isSpawn] [-wait <seconds>] [-P <process name | process id>]  
Decrypts and logs a process's SSL traffic.  
Arguments:  
-pcap <path>, -p <path>  
Name of PCAP file to write  
-host <192.168.1.1:27042>, -H <192.168.1.1:27042>  
connect to remote frida-server on HOST  
-verbose, -v          Show verbose output  
-process <process name | process id>, -P <process name | process id>  
Process whose SSL calls to log  
-ssl <lib>            SSL library to hook  
--isUsb, -U           connect to USB device  
--isSpawn, -f         if spawned app  
-wait <seconds>, -w <seconds>  
Time to wait for the process  
Examples:  
Pcapture -U -f -P [packagename] -v  
Pcapture -U -P [packagename] -v -p [packagename].pcap  
Pcapture -pcap ssl.pcap openssl  
Pcapture -verbose 31337  
Pcapture -pcap log.pcap -verbose wget  
Pcapture -pcap log.pcap -ssl "*libssl.so*" com.bigfacecat.testdemo  
```
### 暂发现问题
* 目前只能使用attach方式，spawn方式仍遇到bug~~(好像是不能修改)~~
* 拦截包修改时可能会遇到界面不刷新问题，需要停止hook后刷新界面，发送后端的数据就会刷新~~(好像是因为此拦截方式对前端界面不影响？)~~

### 最后
* 希望有兴趣的大佬能够指导解决以上仍存在的bug
