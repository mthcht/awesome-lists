rule Virus_Win32_Induc_A_2147627628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Induc.A"
        threat_id = "2147627628"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Induc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "not eof(f1) do begin readln(f1,s); writeln(f2,s);  if pos($implementation$,s)<>0" ascii //weight: 1
        $x_1_2 = "then break;end;for h:= 1 to 1 do writeln(f2,sc[h]);for h:= 1 to 23 do writeln(f2" ascii //weight: 1
        $x_1_3 = ",$$$$+sc[h],$$$,$);writeln(f2,$$$$+sc[24]+$$$);$);for h:= 2 to 24 do writeln(f2," ascii //weight: 1
        $x_1_4 = "x(sc[h]));closefile(f1);closefile(f2);{$I+}MoveFile(pchar(d+$dcu$),pchar(d+$bak$" ascii //weight: 1
        $x_1_5 = ")); fillchar(f,sizeof(f),0); f.cb:=sizeof(f); f.dwFlags:=STARTF_USESHOWWINDOW;f." ascii //weight: 1
        $x_1_6 = "wShowWindow:=SW_HIDE;b:=CreateProcess(nil,pchar(e+$\"$+d+$pas\"$),0,0,false,0,0,0," ascii //weight: 1
        $x_1_7 = "f,p);if b then WaitForSingleObject(p.hProcess,INFINITE);MoveFile(pchar(d+$bak$)," ascii //weight: 1
        $x_1_8 = "pchar(d+$dcu$));DeleteFile(pchar(d+$pas$));h:=CreateFile(pchar(d+$bak$),0,0,0,3," ascii //weight: 1
        $x_1_9 = "0,0);  if  h=DWORD(-1) then exit; GetFileTime(h,@t1,@t2,@t3); CloseHandle(h);h:=" ascii //weight: 1
        $x_1_10 = "CreateFile(pchar(d+$dcu$),256,0,0,3,0,0);if h=DWORD(-1) then exit;SetFileTime(h," ascii //weight: 1
        $x_1_11 = "@t1,@t2,@t3); CloseHandle(h); end; procedure st; var  k:HKEY;c:array [1..255] of" ascii //weight: 1
        $x_1_12 = "char;  i:cardinal; r:string; v:char; begin for v:=$4$ to $7$ do if RegOpenKeyEx(" ascii //weight: 1
        $x_1_13 = "HKEY_LOCAL_MACHINE,pchar($Software\\Borland\\Delphi\\$+v+$.0$),0,KEY_READ,k)=0 then" ascii //weight: 1
        $x_1_14 = "begin i:=255;if RegQueryValueEx(k,$RootDir$,nil,@i,@c,@i)=0 then begin r:=$$;i:=" ascii //weight: 1
        $x_1_15 = "1; while c[i]<>#0 do begin r:=r+c[i];inc(i);end;re(r+$\\source\\rtl\\sys\\SysConst$+" ascii //weight: 1
        $x_1_16 = "$.pas$,r+$\\lib\\sysconst.$,$\"$+r+$\\bin\\dcc32.exe\" $);end;RegCloseKey(k);end; end;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Induc_A_2147627628_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Induc.A"
        threat_id = "2147627628"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Induc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "writeln(f2,$$$$+sc[24]+$$$" ascii //weight: 1
        $x_1_2 = {bb 01 00 00 00 be ?? ?? ?? ?? 8b 16 8b c7 e8 ?? ?? ?? ff e8 ?? ?? ?? ff e8 ?? ?? ?? ff 83 c6 04 4b 75 e7 bb 17 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

