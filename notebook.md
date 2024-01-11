<!--  
    关于std:IPConn:
        windows:
            1. 只能使用 ip4:0，不能指定传输层/ICMP协议
            2. IPConn只能接收到传输层没有被Listen的IP Packet
            3. 多个IPConn都能读取到同一个IP-Packet
            4. 不能写数据[ref](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2#limitations-on-raw-sockets)
        Linux:
            1. 不支持 ip4:0, proto 必须指定传输层/ICMP协议
            2. IPConn能读取到所有期望的IP Packet
            3. 多个IPConn都能读取到同一个IP-Packet

    因此：
        应该bind对应的协议端口，避免数据包混杂；对于recv, Windows只能用户层过滤，Linux可以使用BPF
 -->


 <!-- 
    IPConn.Write() 超过MTU会自动分包
 
  -->

  <!-- 
  
    todo: 提取tcpip.Endpoint

   -->