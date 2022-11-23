# volatility-master使用命令

```
python2 vol.py -f memory.raw imageinfo  #查看系统版本信息
python2 vol.py -f memory.raw --profile=WinXPSP2x86 pslist      #列出进程
python2 vol.py -f memory.raw --profile=WinXPSP2x86 psscan      #列出进程
python2 vol.py -f memory.raw --profile=WinXPSP2x86 cmdscan     #查看cmd命令历史
python2 vol.py -f memory.raw --profile=WinXPSP2x86 cmdline     #查看cmd命令历史
python2 vol.py -f memory.raw --profile=WinXPSP2x86 consoles    #查看cmd命令历史
python2 vol.py -f memory.raw --profile=WinXPSP2x86 iehistory  #查看ie浏览器历史记录
python2 vol.py -f memory.raw --profile=WinXPSP2x86 filescan | grep ".txt\|.doc\|.zip\|.png"  #通过关键字查找文件，使用反斜杠进行转义
python2 vol.py -f memory.raw --profile=WinXPSP2x86   dumpfiles -Q 0x00000000022352c8 -D /home/kali  #文件导出，-Q参数是文件id；-D参数是导出目录
python2 vol.py -f memory.raw --profile=WinXPSP2x86 memdump -p 596 -D /home/kali  进程信息导出，-p参数是进程的PID；-D参数是导出目录
python2 vol.py -f memory.raw --profile=WinXPSP2x86 screenshot --dump-dir=/home/kali    #屏幕截图
python2 vol.py -f memory.raw --profile=WinXPSP2x86 userassist     #查看进程运行次数
python2 vol.py -f memory.raw --profile=WinXPSP2x86 notepad        #查看notepad编辑内容
python2 vol.py -f memory.raw --profile=WinXPSP2x86 clipboard      #查看粘贴板内容
python2 vol.py -f memory.raw --profile=WinXPSP2x86 svcscan        #查看服务



```

