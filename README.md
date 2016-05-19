#TCPStats
Project for [PDS](https://www.fit.vutbr.cz/study/courses/index.php?id=10921) (Data Communications, Computer Networks and Protocols) course at [FIT BUT](https://www.fit.vutbr.cz/). TCPStats creates statistics for a single TCP stream in given PCAP file. The statistics are presented in form of summary tables and charts in a web page.

#Usage
The following command will generate statistic for the given `file` and store them in the `log/` folder:
```
$ ./tcpstats.py file
```
You can view that statistics by opening the `tcpstats.html` ([link](tcpstats.html)).
