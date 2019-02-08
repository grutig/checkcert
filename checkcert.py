#!/usr/bin/python
""" checkcert 1.01

manage let's encrypt certificate renewal
----------------------------------------

This is free software released under MIT License

Copyright (c) 2015, 2019 Giorgio L. Rutigliano
(www.iltecnico.info, www.i8zse.eu, www.giorgiorutigliano.it)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


"""
import subprocess
import datetime
import configparser
import os
import smtplib
from email.message import EmailMessage
import sys
import syslog

def terminate(exitmsg: str):
    """
    Prints exit message and terminate program
    :param exitmsg: exit message
    :return: None
    """
    print(exitmsg)
    sys.exit(1)

def expdays(cert: str) -> int:
    """
    Get expiration date from certificate
    :param cert: certificate name (str)
    :return: days until expiratione (int)
    """
    cmd = 'date --date="$(openssl x509 -in ' + cert + ' -noout -enddate | cut -d= -f 2)" --iso-8601'
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    p.wait()
    exp = [int(i) for i in out.decode().split('-')]
    d1 = datetime.datetime.now()
    d2 = datetime.datetime(*exp)
    return (d2 - d1).days

####################
#load configuration#
####################
syslog.openlog("CHECKCERT")
cfile='checkcert.cfg'
config = configparser.ConfigParser()
if not(os.path.isfile(cfile)):
    terminate("Missing configuration file ("+cfile+")")
config.read(cfile)
sitelist=[] # site elements
try:
    sect="base"
    certname = config.get(sect,"certname")
    deadline = config.getint(sect,"deadline")
    reloadapache = config.get(sect,"reloadhttp")
    sect="notify"
    efrom = config.get(sect,"from")
    eto = config.get(sect,"to", fallback='')
    esmtp = config.get(sect,"smtp")
    eport = config.getint(sect,"port",fallback=25)
    essl = config.get(sect, "ssl", fallback="false").lower() == 'true'
    epass = config.get(sect,"pass",fallback='')
    for (rpath, doms) in config.items('domains'):
        if not (os.path.isdir(rpath)):
            terminate("Non-existent web root directory (" + rpath + ")")
        if (doms==''):
            terminate("Missing domanin list (" + rpath + ")")
        sitelist.append([rpath,[x.strip() for x in doms.split(';')]])
except Exception as e:
    buf="Configuration error: " + e.message
    syslog(buf)
    terminate(buf)

####################
#check certificates#
####################
renewlist=[]
errorlist=[]
for domdata in sitelist:
    certfile = '/etc/letsencrypt/live/' + domdata[1][0] + '/' + certname
    days = 0
    if os.path.isfile(certfile):
        days = expdays(certfile)
    syslog.syslog("Domain: "+ domdata[1][0] + ', expiration: ' + str(days) + ' days')
    flForce=False
    if len(sys.argv) == 2 and sys.argv[1].lower() == "force":
        flForce=True
    if days < deadline or flForce:
        syslog.syslog("Domain: " + domdata[1][0] + ', request '+ ('force renewal' if flForce else 'renewal'))
        # renew certificate
        cmd = '/usr/bin/certbot certonly -n --webroot -w '
        cmd += domdata[0]
        for i in domdata[1]:
            cmd += ' -d ' + i
        cmd += ' --renew-by-default --agree-tos --email ' + efrom
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        p.wait()
        if p.returncode!=0:
            # log error to syslog
            syslog.syslog("Domain: " + domdata[1][0] + ', ' + cmd + ' returned exit code '+str(p.returncode))
            err=err.decode()
            if err=="":
                err="No error messages, return code: "+str(p.returncode)
            syslog.syslog("Domain: " + domdata[1][0] + ', ' + err)
            errorlist.append([domdata[1][0],err])
            continue
        # re-check certificate expiration date after renew
        days=0
        if os.path.isfile(certfile):
            days = expdays(certfile)
        if days < deadline:
            syslog.syslog("Domain: " + domdata[1][0] + ' NOT renewed!')
            errorlist.append([domdata[1][0],'Wrong certificate expiration date after renewal'])
        else:
            syslog.syslog("Domain: " + domdata[1][0] + ' renewed ')
            renewlist.append(domdata[1][0])

if (len(errorlist)>0 or len(renewlist)>0) and eto!='':
    # notification email
    subj="Certificate(s) renew notification"
    f=open("checkcert.tmpl","r")
    buf=f.read()
    f.close()
    if len(renewlist)>0:
        buf=buf.replace("%%renewlist%%","\n".join(renewlist))
        # reload server
        p = subprocess.Popen(reloadapache, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        p.wait()
        rcode = p.returncode
        if rcode==0:
            syslog.syslog("Webserver reloaded")
        else:
            syslog.syslog("Error reloading webserver: "+err.decode())
    else:
        buf=buf.replace("%%renewlist%%","None\n")
    if len(errorlist)>0:
        subj+=" (errors)"
        ebuf=''
        for err in errorlist:
            ebuf+=err[0]+":\n"
            ebuf+=err[1]+"\n"
    else:
        ebuf="None\n"
    buf=buf.replace("%%errorlist%%",ebuf)

    ## send message
    try:
        msg = EmailMessage()
        msg['Subject'] = subj
        msg['From'] = efrom
        msg['To'] = eto.split(';')
        msg.set_content(buf)
        if essl:
            s = smtplib.SMTP_SSL(esmtp, eport, timeout=30)
        else:
            s = smtplib.SMTP(esmtp, eport, timeout=30)
        if epass!="":
            s.login(efrom, epass)
        s.send_message(msg)
        s.quit()
    except Exception as e:
        syslog.syslog("Error sending notification email: " + e.strerror)
