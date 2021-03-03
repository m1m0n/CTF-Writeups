
## Quals: Egypt and Tunisia National Cyber Security CTF 2019. [Want More Biscuits]

![](https://cdn-images-1.medium.com/max/3038/1*jU7GomtZ1ObzD4QXDgugLQ.jpeg)

Hello CTF Player, This is My Write up For **Want More Biscuits** Challenge From Cyber Talents Quals Round 2019 .
 ***NOTE***:I Will Use Different Stuff To Solve This Challenge So Keep Up With Me!
>  Link : [http://35.225.49.73/wantmorebiscuits/src/](http://35.225.49.73/wantmorebiscuits/src/)

***1 — Recon Phase***

First Of All Lets Explore The Website By Checking The Page Source ,Request Headers and Response Headers but Nothing interesting in The Page Source

Lets Send Request And Check The Response Headers.

![](https://cdn-images-1.medium.com/max/2000/1*ucYpG1wqBIgiUf5DQId2Cw.png)

***.headers*** Returns a Dictionary, and i Loop Through This it.

![Response Headers](https://cdn-images-1.medium.com/max/3766/1*DD-XUO1jKx8sYd32M5LQhQ.png)

HUMM! I see That The Value Of **userCookie** is Mixed ****between ***Base64 ***and ***URL Encoding***, So let’s Try To Decode This.

![Value Of userCookie](https://cdn-images-1.medium.com/max/2236/1*T_dvpfaIV2WXt8-GxIE3bg.png)

WOW! It is*** PHP Serialized Object!***

So We Need The Source Code of the Backend but, How Could We Get it!

Let’s Try to Use a Tool Like [**Dirsearc](https://github.com/maurosoria/dirsearch)h** — or Whatever Tool You Like — To Brute Force Directories and Files in The Website.

![](https://cdn-images-1.medium.com/max/2182/1*qmRA4EbBK8PTBTpLgWJKqQ.png)

Yeah, We Found Copy Of Backup in ***index.php~***

![source code of the website](https://cdn-images-1.medium.com/max/2098/1*DtC5eI7cTUArLaQ5XJIEaQ.png)

After Understanding ***PHP Object Injection*** From This [*Tutorial](https://www.youtube.com/watch?v=gTXMFrctYLE)*. Lets Exploit This Vulnerability.

***2 — Exploitation Phase.***

![Final Payload](https://cdn-images-1.medium.com/max/2000/1*3jcp7AAndtzxtdjs_M8SXA.png)

Now We Need To Set The Value Of ***userCookie ***to : *Tzo2OiJNeUV4ZWMiOjE6e3M6NzoiY29tbWFuZCI7czo2OiJscyAtbGEiO30=*

![Send a new Request with New Value Of Cookie](https://cdn-images-1.medium.com/max/2516/1*64RjafTq51fDjw3oHdCSNA.png)

After Running This Script , I Found This :

![](https://cdn-images-1.medium.com/max/2126/1*VenN9YS5-nS9_B6ZZMfcHA.png)

Yeah It Works :) , Now Open This File: ***Flag_FGRRDAKKUGBSKKIUHDLLMNEJDK.txt***

![Yeah We Get The Flag :D](https://cdn-images-1.medium.com/max/2000/1*F1yg89hkECU5uWpPbC9Qcw.png)

Finally, This is My First Write-up May be It is not the Best One But I’m Doing My Best — So Your Feedback Will Be Appreciated ^_^ —

If You Need The Solutions For The Rest Of Web Challenge , You Can Find [It Here](https://medium.com/@mohamedrserwah/quals-egypt-and-tunisia-national-cyber-security-ctf-2019-21d482ca8ab4) and The Solutions Of Competition Challenges Is [Here](https://medium.com/@mohamedbatal07/write-up-egypt-and-tunisia-national-cyber-security-ctf-2019-a81c24292d5e)

Special Thanks For **Serwah** And **Anwar** For This Awesome Write Up ❤

Thanks For Reading :)
