# FastPwn

> V2.1
> 新增 [Auto_PerUti.py] 
> 主要用于针对持久化控制目标主机后通过Tmux进行的的一个自动化flag获取、提交管理操作
> 当前的FastPwn缺点也很明显，当有些程序不能长时间挂起时，我们的持久化控制也将失效，即只可以单次利用.....

## exploit
```bash
❯ python exploit.py 
❯ python exploit.py [exp_mod] 
❯ python exploit.py [Ip] [Port]
❯ python exploit.py [Ip] [Port] [exp_mod]


# Edit values:
      - RemPro()
           - elf_addr
           - pro_libc
           - enable_Onegadgets
      - exp()
```

### Dynamic presentation

![](https://github.com/da1sy/da1sy/raw/master/exploit.gif)



## Awd-Exploit

```bash
❯ python Autopwn.py [exp_mod] 

# Tmux_Useing    : 
❯ tmux ls
❯ tmux a -t tmux_id

# Edit values:
     - main()
          - ip & port & cmd & flag_head
          - ip和port 同时决定着tmux会话的创建规则
          - attack():
              - 发送cat flag前的接收参数
              - Submit_flag()
                   - url
                   - headers {Token & Content-type}
                   - data （接收反馈时的编码问题）

```

### Dynamic presentation

![](https://github.com/da1sy/da1sy/raw/master/auto_pwn.gif)


## Auto_PerUti.py
```bash
# Bash_Useing
❯ python Auto_PerUti.py 
[T.T] Flag提交错误!
XCCTF{22ee2bc5dcc3afe1255e1db441004a35a9e9dd2d}
[+] Content : {"error":40307,"msg":"Flag 错误！"}

[T.T] Flag提交错误!
XCCTF{8e0b2348b5365a5b5fabd638f317bb226edf421d}
[+] Content : {"error":40307,"msg":"Flag 错误！"}

[T.T] Flag提交错误!
```
![](https://gitee.com/oneda1sy/da1sy_picture/raw/master/img/20211015185128.png)