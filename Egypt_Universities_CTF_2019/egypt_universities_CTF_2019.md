
## Egypt Universities CTF 2019

Hello and Welcome , This is Quick Write up for Some Challenges from Egypt Universities CTF 2019 Organized by CyberTalents.

It Was an Awesome Competition and all teams have high spirit and great performance

![](https://cdn-images-1.medium.com/max/3812/1*R6Sp6sMYP4a9N3gbhG9pDw.png)

## **Digital Forensics Category**

***1 — pekz (Easy — 50 points)***

In This One We had a ***pcap (Packet Capture)***file, Inside It There are some HTTP Requests and TCP Stream

![](https://cdn-images-1.medium.com/max/3838/1*yuQdyo1r1gZWT9MTKnjCkg.png)

First Of all Let’s do some Recon Stuff to determine What We Actually Have in this file .

***strings ***: to Show all printable characters in this file

***grep: ***print lines that match given pattern and -***i*** to ignore the case .

```$strings pekz.pcap | grep -i “flag”*```

![](https://cdn-images-1.medium.com/max/3342/1*4tD7XiFU6gOHBr51WADeyA.png)

Alright, We Can make a Simple Bash Script to get the flag
```bash
#!/usr/bin/env bash
strings pekz.pcap | grep -i “flag{.*}” | cut -d “\”” -f 2
```
***FLAG{0h_dump_is_ez_recover_is_eazi3r!!}***

***2 — Keep Calm (Medium — 100 Points)***

In This Challenge We had this GIF file

![Scatter](./scatter.gif)
First Of All we Need to slow down the speed of this GIF to know What We have , You Can Use This [Website](https://ezgif.com/speed) to Change the speed OR Simply you Can Use ***convert*** in linux to convert the GIF to PDF or even PNG

```bash
$convert scatter.gif scatter.pdf # convert to PDF
$convert -verbose -coalesce scatter.gif scatter.png # Convert to PNG
```
OR ***gif2png*** to convert each Frame in GIF to PNG

```bash
$gif2png scatter.gif
```

Now We Have this chars

```arr = [“zND”, “zg5”,”MTI”,”U2N”,”MAo=”]```

It Looks Like*** base64*** , Let’s Try to Decode it, BUT nothing useful because of it isn’t in the right order.

HUMMM , I think That We Need To Write a simple Script to print out all Possible Permutation from this Array.

We Have 5 Element So We Will Print*** 5!=120 ***Possible Flag , but We Can Decrease This Number .

I See That ***MAo= ***Should be The last Part Of The Base64 Encoded String.

Now We Have ***4!=24*** Possible Flag, Let’s Start To Write our Script.

```python
import base64

arr = ["zND", "zg5","MTI","U2N"]
flag = ""

for i in range(0, 4):
	for j in range(0, 4):
		if j != i :
			for k in range(0, 4):
				if k != i and k!= j:
					for l in range(0, 4):
						if l != i and l != j and l != k:
							flag += arr[i] + arr[j] + arr[k] + arr[l] + "MAo="
							print(flag + " : "+ base64.b64decode(flag))
							flag = ""
```
After Running This Script I Found Unreadable Output but Two of Them Catch My Attention , The **First** and The **Last** one.

![](https://cdn-images-1.medium.com/max/2000/1*BGe0LTn_lOeeR4u8ekVlqA.png)

Probably One of them is the Correct flag let’s try to Submit it!

LOL, The Correct One is : ***1234567890***

Another Short and Handy One Using [itertools](https://docs.python.org/2/library/itertools.html) in Python.

```py
import base64, itertools

arr = ["zND", "zg5","MTI","U2N"]
temp = list(itertools.permutations(arr))

for i in temp:
	flag = "".join(i) + "MAo="
	print(flag + " : "+ base64.b64decode(flag))
```
## Reverse Engineering Category

***1 — login (Easy — 50 Points)***

In This Challenge We Have File, Let’s use ***file*** Command to determine file type.

![](https://cdn-images-1.medium.com/max/3816/1*Yx9-ZcLvu6rLfs-BvQUm6Q.png)

Well, It’s an ELF executable file, let’s try to execute it..

![](https://cdn-images-1.medium.com/max/2014/1*wTrFf0or4oHgQFci-mPfJA.png)

but, It Requires Two Parameters , ***Username*** and ***Password***

Let’s Try to Put any Random Username and Password to See What Will happen!

![Wrong username and password](https://cdn-images-1.medium.com/max/2000/1*kGpvjwoSn4-ATkytGd19dw.png)

HUMM, I Expect That there is Function to Compare Between Input and the Correct username and password.

Let’s Try to use ***ltrace: T***o Trace Library Functions Calling like printf() or strcmp()**.**

![](https://cdn-images-1.medium.com/max/2000/1*vqDVZPkjk7ScMmpL_fSHvw.png)

as Expected it Compares Between Input and username, Till Now i Can See That the Correct Username is ***cybertalent.***

By Repeating ,with the Correct username

![](https://cdn-images-1.medium.com/max/2000/1*QAbSOixCVqHRQbv5EKOgFA.png)

We Can See That The Password is ***P@ss, ***and the flag is : ***flag{cybertalent:P@ss}***

OR Simply You Can Use ***strings ***and*** ***by Guessing You Will See the flag!

![](https://cdn-images-1.medium.com/max/2000/1*hjN0Ai6lLQZyJK0P3w6J7g.png)

## Cryptography Category

***1 — Irving Secret(Medium — 100 Points)***

We Have ***pcap*** File, So Let’s Open It With ***Wireshark***

![](https://cdn-images-1.medium.com/max/3826/1*mAlO75JroxX1dy8JbZ0lPg.png)

![](https://cdn-images-1.medium.com/max/2562/1*jGyFWwD7DgIxwcMkqPGKsQ.png)

Literally We Didn’t Know What We have To Do, So We Need HINT!

*“This Packets Are a Stream Of **JPEG **Image but, It was Shifted by **ROT13**”*

The Hint is Clear!

Alright, We Will take this Stream and Decrypt it Using [ROT13](https://rot13.com/)

![](https://cdn-images-1.medium.com/max/3838/1*wIQC9rph_Wi_UJ6z2gDLdA.png)

Then We Need To Convert This RAW Stream To JPEG Image

After a Little Bit of Searching I Found This [Website](https://tomeko.net/online_tools/hex_to_file.php?lang=en) , To Do What We Need

![](https://cdn-images-1.medium.com/max/2000/1*kVLVZukposyOENBRbp228g.png)

Then I Downloaded the image

![](https://cdn-images-1.medium.com/max/3812/1*7xZpVmjHFnhk86v1Q208zg.png)

![](https://cdn-images-1.medium.com/max/2592/1*Du1IwYf3gxWaarbbpVnUWA.jpeg)

Yeah, It Works Well^_^

and The Flag is the md5sum of this Image.

***flag{0eed48c187f783159a6ab6dba559d458}***

OR You Can Use ***xxd*** , You Will Get The Same Result
```bash
$xxd -r -p stream file.jpg
```
The Funny Part Is We Couldn’t Solve it During the Competition, Because When I Converted This Raw Stream to JPEG it didn’t work as I expected
It Looks Like That I Made a Mistake , But Anyway It Has Been Solved :D

## ***Web Security Category***

You Can Find an awesome Write-up for web Challenges [Here](https://medium.com/@sasaxxx777/egypt-universities-ctf-2019-write-up-web-challenges-3249afd6f40) by Moustafa Anwar

Thanks For Reading
