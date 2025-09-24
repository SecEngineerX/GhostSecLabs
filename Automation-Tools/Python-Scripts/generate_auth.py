# generate_auth.py
import random, datetime 
months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"] 
now = datetime.datetime.now() 
month = months[now.month-1] 
hosts = ["server1","web01","db01"] 
ips = ["203.0.113.45","198.51.100.22","192.0.2.5","10.0.0.5"] 
users = ["admin","root","bob","alice","invalid_user"] 
lines = [] 

def ts(offset_seconds=0):
    t = now - datetime.timedelta(seconds=offset_seconds) 
    return t.strftime("%b %d %H:%M:%S")

# generate noisy normal entries
for i in range(100): lines.append(f"{ts(random.randint(1000,5000))} {random.choice(hosts)} sshd[{1000+random.randint(0,4000)}]: Accepted password for {random.choice(['alice','bob'])} from {random.choice(['192.0.2.10','10.0.0.7'])} port {40000+random.randint(0,3000)} ssh2")

# generate brute-force style bursts for two IPs
for ip in ["203.0.113.45","198.51.100.22"]: 
    start = random.randint(0,200) 
    for j in range(18): 
# 18 failures within a short window
        lines.append(f"{ts(start+j)} server1 sshd[{2000+random.randint(0,1000)}]: Failed password for invalid user {random.choice(users)} from {ip} port {50000+random.randint(0,2000)} ssh2")
# some other scattered failed attempts
for i in range(20): 
    lines.append(f"{ts(random.randint(500,2000))} web01 sshd[{3000+random.randint(0,2000)}]: Failed password for {random.choice(users)} from {random.choice(ips)} port {45000+random.randint(0,3000)} ssh2")
# shuffle to simulate real arrival order
random.shuffle(lines) 
with open("auth.log", "w") as f: 
    for L in lines: f.write(L + "\n")
print("auth.log generated ({} lines)".format(len(lines)))
