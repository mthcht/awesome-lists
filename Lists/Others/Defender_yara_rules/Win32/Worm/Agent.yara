rule Worm_Win32_Agent_2147565723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Agent"
        threat_id = "2147565723"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "system sys process.exe" ascii //weight: 1
        $x_1_2 = "windows\\Windows Medoc\\" ascii //weight: 1
        $x_1_3 = "windows_dxgc.exe" ascii //weight: 1
        $x_1_4 = {43 3a 5c 00 44 3a 5c 00 45 3a 5c 00 46 3a 5c 00 47 3a 5c 00 48 3a 5c 00 6b 3a 5c 00 52 3a 5c 00 53 3a 5c 00 54 3a 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Agent_2147565723_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Agent"
        threat_id = "2147565723"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mvumisc.exe" ascii //weight: 1
        $x_1_2 = "KAENA_HOOK" ascii //weight: 1
        $x_1_3 = "ZwOpenProcess" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\MSrtn\\value1" ascii //weight: 1
        $x_1_5 = "aUtoRuN.iNF" wide //weight: 1
        $x_1_6 = "ecalc.exe" wide //weight: 1
        $x_1_7 = "ntspecd" wide //weight: 1
        $x_1_8 = "writeln(f2,$$$$+sc[24]+$$$);$)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Agent_CC_2147583769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Agent.CC"
        threat_id = "2147583769"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 (81 ea ?? ?? ?? ??|83 ea ??) e8 ?? ?? ff ff 8b 55 f4 8d 45 f8 e8 ?? ?? ff ff 43 4e 75 (d9|dc)}  //weight: 10, accuracy: Low
        $x_10_2 = "Avenger by NhT" ascii //weight: 10
        $x_1_3 = "explorer.exe" ascii //weight: 1
        $x_1_4 = "svchost.exe" ascii //weight: 1
        $x_1_5 = "haha.exe" ascii //weight: 1
        $x_1_6 = "msnworm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Agent_N_2147592582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Agent.N"
        threat_id = "2147592582"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "if exist \"%s\" goto 1" ascii //weight: 1
        $x_1_2 = "%s%s.bat" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\WAB\\WAB4\\Wab File Name" ascii //weight: 1
        $x_1_5 = "%s.%s@%s" ascii //weight: 1
        $x_1_6 = "%s%s.zip" ascii //weight: 1
        $x_1_7 = "%s.doc.exe" ascii //weight: 1
        $x_1_8 = "%s.txt.exe" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Agent_T_2147594812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Agent.T"
        threat_id = "2147594812"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "910"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Look how wasted Paris Hilton is, after she got jailed :(" ascii //weight: 1
        $x_1_2 = "You and Me !!! .... looook :p" ascii //weight: 1
        $x_1_3 = "Look at my photos hihi :p" ascii //weight: 1
        $x_1_4 = "Hey please accept my photos :o !!" ascii //weight: 1
        $x_1_5 = "A photo with me and my best friend :$ !!" ascii //weight: 1
        $x_1_6 = "This is me totaly naked :o please dont send to anyone else" ascii //weight: 1
        $x_1_7 = "Look what i found on the NET :o Jessica Alba NUDE !!" ascii //weight: 1
        $x_1_8 = "bak sana  Paris Hilton ne hale gelmis hapiste :(" ascii //weight: 1
        $x_1_9 = "Sen ve Ben !!! .... BAK :p" ascii //weight: 1
        $x_1_10 = "Baksana benim fotograflara hihi :p" ascii //weight: 1
        $x_1_11 = "Hey benim fotolarimi kabul et :o !!" ascii //weight: 1
        $x_1_12 = "Iyi arkadasimla fotorafdayim :$ !!" ascii //weight: 1
        $x_1_13 = "benim bu ciplak fotoda :o ama baskasina yollama" ascii //weight: 1
        $x_1_14 = "bak ne buldum :o Jessica alba ciplak !!" ascii //weight: 1
        $x_1_15 = "Regarde comment Paris Hilton parait efondr" ascii //weight: 1
        $x_1_16 = "s qu'elle ai " ascii //weight: 1
        $x_1_17 = " jeter en prison :(" ascii //weight: 1
        $x_1_18 = "Toi et moi !!! .... regarde :p" ascii //weight: 1
        $x_1_19 = "Regarde mes photos :p" ascii //weight: 1
        $x_1_20 = "Hey s'il te plait accepte mes photos :o !!" ascii //weight: 1
        $x_1_21 = "Une photo de moi et mon meilleur ami :$ !!" ascii //weight: 1
        $x_1_22 = "C'est moi totalement nu :o s'il te plait ne l'envoie a personne d'autre" ascii //weight: 1
        $x_1_23 = "Regarde ce que j'ai trouv" ascii //weight: 1
        $x_100_24 = "NICK new[%s][%iH]%s" ascii //weight: 100
        $x_100_25 = "new.txt" ascii //weight: 100
        $x_100_26 = "USER %s" ascii //weight: 100
        $x_100_27 = "JOIN %s" ascii //weight: 100
        $x_100_28 = "PING :" ascii //weight: 100
        $x_100_29 = "PONG :%s" ascii //weight: 100
        $x_100_30 = "NICK [%s][%iH]%s" ascii //weight: 100
        $x_100_31 = "KICK" ascii //weight: 100
        $x_100_32 = ".baby" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_100_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Agent_AB_2147595755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Agent.AB"
        threat_id = "2147595755"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "141"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {8b c1 8b f7 33 cb 03 f0 03 f9 83 f1 ff 83 f0 ff 33 cf 33 c6 83 c2 04 81 e1 00 01 01 81}  //weight: 100, accuracy: High
        $x_10_2 = "Setup.zip.exe" ascii //weight: 10
        $x_10_3 = "p2pex.zip.exe" ascii //weight: 10
        $x_10_4 = "www.regione.calabria.it" ascii //weight: 10
        $x_10_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_1_6 = "You Are Empty.zip.exe" ascii //weight: 1
        $x_1_7 = "Windows Xp on PsP.zip.exe" ascii //weight: 1
        $x_1_8 = "Half Life 2 Episode One.zip.exe" ascii //weight: 1
        $x_1_9 = "DOOM 3 Full 3 CD Bonus.zip.exe" ascii //weight: 1
        $x_1_10 = "Windows Vista Ultimate SP3 2007 Crack.zip.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Agent_AC_2147596354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Agent.AC"
        threat_id = "2147596354"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GET /chr/907/nt.exe HTTP/1.1" ascii //weight: 10
        $x_10_2 = "Host: www6.badesugerwakirpos.com" ascii //weight: 10
        $x_10_3 = "http://www6.badesugerwakirpos.com/chr/907/nt.exe" ascii //weight: 10
        $x_1_4 = "Accept: */*" ascii //weight: 1
        $x_1_5 = "Accept-Encoding: gzip, deflate" ascii //weight: 1
        $x_1_6 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Agent_AD_2147596428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Agent.AD"
        threat_id = "2147596428"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "133"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {8a c2 30 44 24 6c 8b 4c 24 6c c1 e9 08 32 c8 88 4c 24 6d 8b 54 24 6c c1 ea 10 32 d0}  //weight: 100, accuracy: High
        $x_10_2 = "%WINDIR%\\tpup.exe" ascii //weight: 10
        $x_10_3 = "C:\\WINDOWS\\tpup.exe" ascii //weight: 10
        $x_10_4 = "VC20XC00U" ascii //weight: 10
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "WSASend" ascii //weight: 1
        $x_1_9 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Agent_DA_2147600031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Agent.DA"
        threat_id = "2147600031"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "231"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "AmirCivil Worm.pdb" ascii //weight: 100
        $x_100_2 = "You infected by irvirus TEAM" ascii //weight: 100
        $x_10_3 = "\\taskmrg.exe" ascii //weight: 10
        $x_10_4 = "\\Driver32.exe" ascii //weight: 10
        $x_10_5 = "\\Sex Story.txt.exe" ascii //weight: 10
        $x_10_6 = "\\SexStory.txt" ascii //weight: 10
        $x_1_7 = "xxx.3gp" ascii //weight: 1
        $x_1_8 = "crims.jpg" ascii //weight: 1
        $x_1_9 = "sex webshot2008.scr" ascii //weight: 1
        $x_1_10 = "xnxx screensaver2008.scr" ascii //weight: 1
        $x_1_11 = "sex web shot.scr" ascii //weight: 1
        $x_1_12 = "xnxx screen saver.scr" ascii //weight: 1
        $x_1_13 = "exploit for vista.txt" ascii //weight: 1
        $x_1_14 = "sex movie list.dat" ascii //weight: 1
        $x_1_15 = "www.symantec.com" ascii //weight: 1
        $x_1_16 = "www.kaspersky.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Agent_DV_2147600504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Agent.DV"
        threat_id = "2147600504"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 6c 40 00 8d 44 24 14 50 ff d6 6a 00 8d 4c 24 14 51 ff 15 98 60 40 00 68 70 6c 40 00 8d 54 24 14 52 ff d6 8d 84 24 18 01 00 00 50 8d 4c 24 14 51 ff d6 6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 c0 8d 54 24 28 52 ff 15 10 61 40 00 83 f8 ff 74 15 6a 00 8d 4c 24 10 51 6a 0a 68 64 6c 40 00}  //weight: 1, accuracy: High
        $x_1_2 = "c:\\Program Files\\ctfmone.exe" ascii //weight: 1
        $x_1_3 = "c:\\Program Files\\ctfmona.exe" ascii //weight: 1
        $x_1_4 = "4b324fc8-1670-01d3-1278-5a47bf6ee188" ascii //weight: 1
        $x_1_5 = "risinidaye" ascii //weight: 1
        $x_1_6 = "%smdmscan%d.log" ascii //weight: 1
        $x_1_7 = "\\%s\\pipe\\BROWSER" ascii //weight: 1
        $x_1_8 = "Sending payload2...finish" ascii //weight: 1
        $x_1_9 = "Sending payload1...finish" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Agent_U_2147607881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Agent.U"
        threat_id = "2147607881"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {63 74 66 6d 6f 6e 2e 65 78 65 00 00 00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 5c 64 6c 6c 2e 64 6c 6c 00 00 00 00 5c 73 79 73 74 63 6d 2e 73 79 73 00}  //weight: 2, accuracy: High
        $x_2_2 = "WNetEnumResourceA" ascii //weight: 2
        $x_2_3 = "OpenProcess" ascii //weight: 2
        $x_2_4 = "CreateRemoteThread" ascii //weight: 2
        $x_2_5 = "CopyFileA" ascii //weight: 2
        $x_2_6 = "GetProcessWindowStation" ascii //weight: 2
        $x_1_7 = {5c c4 cf c4 fe ca d0 b9 ab ce f1 d4 b1 cc e1 d7 ca b5 c8 bc b6 b1 ea d7 bc 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*))) or
            (all of ($x*))
        )
}

