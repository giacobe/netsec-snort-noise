#!/usr/bin/env python3
import datetime as dt, hashlib, re
LAB_ID="polymorphic-snort-1"; SYSTEM_PASSWORD="snortSystemV1"; LEVEL_PASSWORD_ROOT="snortStageV1-"
def _cmdline():
    result={}
    for item in open("/proc/cmdline",encoding="utf-8").read().split():
        if "=" in item: key,value=item.split("=",1); result[key]=value
    return result
def encode_date(date): return format(int(date.strftime("%Y%m%d")),"X")
def identity():
    values=_cmdline(); email=bytes.fromhex(values["polylab_email_hex"]).decode().strip().lower(); date=dt.datetime.strptime(values["polylab_date"],"%Y-%m-%d").date()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email) or values.get("polylab_code","").upper()!=encode_date(date): raise RuntimeError("Invalid PolyLab identity")
    return email,date,encode_date(date)
def stage_seed(stage):
    email,date,_=identity(); fields=("polylinux-seed-v1",LAB_ID,email,date.isoformat(),SYSTEM_PASSWORD,LEVEL_PASSWORD_ROOT+str(stage),str(stage))
    return hashlib.sha256(b"".join(value.encode()+b"\0" for value in fields)).digest()
def derive(stage,label,length=32): return hashlib.sha256(stage_seed(stage)+label.encode()+b"\0").digest()[:length]
def number(stage,label,minimum,maximum): return minimum+int.from_bytes(derive(stage,label,8),"big")%(maximum-minimum+1)
def noise_addresses():
    start=number(1,"noise-address-start",30,69)
    return ["10.0.0.%d"%(30+((start-30+offset*7)%50)) for offset in range(5)]
def stage3_decoy():
    return (4444,5555,6666,7777,8888)[number(3,"port-index",0,4)],derive(3,"hex-marker",8)[:4]
