# 备份分支：

使用net.IPConn配合bpf实现，已经实现功能，但存在一个问题：

***会从net.IPConn中读取到重组后的tcp segment。***

- 重组应该是在IP stack中发生的，因为wireshake抓包，并没有被合并的数据包，每个IP包都有DF标志，说明发送方是没有问题。

- 重组一般发生在这种情况下：

  | IP ID | seq  | ack  | tcp payload | tcp flags |
  | ---- | ---- | ---- | ----------- | --------- |
  | 1    | 0    | 11   | 3           | ack       |
  | 2    | 3    | 11   | 2           | ack       |
  | 3    | 5    | 11   | 7           | ack\|psh  |

​	那么从conn读取到的是2、3合并的数据包，整个tcp payload大小为9，合并时会修改IP、TCP的相关字段，除了TCP checksum是错误的，其他都是正确的。

- 可以运行 `tcp/bpf_linux_test.go:Test_Connect` 测试复现。





