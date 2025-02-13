rule Backdoor_Win32_Small_2147491548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Small"
        threat_id = "2147491548"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "117"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "drivers\\system.exe" ascii //weight: 50
        $x_50_2 = {68 74 74 70 3a 2f 2f 61 72 70 2e 31 38 31 38 (30|2d|39) (30|2d|39) 2e 63 6e 2f 61 72 70 2e 68 74 6d}  //weight: 50, accuracy: Low
        $x_2_3 = "rover" ascii //weight: 2
        $x_2_4 = "wpcap.dll" ascii //weight: 2
        $x_2_5 = "myexe" ascii //weight: 2
        $x_2_6 = "drivers\\npf.sys" ascii //weight: 2
        $x_2_7 = "Packet.dll" ascii //weight: 2
        $x_2_8 = "WanPacket.dll" ascii //weight: 2
        $x_2_9 = "_deleteme.bat" ascii //weight: 2
        $x_2_10 = ":try" ascii //weight: 2
        $x_2_11 = "if   exist" ascii //weight: 2
        $x_1_12 = "-port 80 -insert" ascii //weight: 1
        $x_1_13 = "-idx 0 -ip" ascii //weight: 1
        $x_1_14 = "-idx 1 -ip" ascii //weight: 1
        $x_1_15 = "-idx 2 -ip  open" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_50_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_50_*) and 9 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Small_IR_2147600680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Small.IR"
        threat_id = "2147600680"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2c 00 43 57 44 45 00 4a 45 43 58 5a 00 44 00 51 00 54 00 43 00 52 00 53 00 45 00 3a 00 5b 00 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 41 74 6c 41 78 57 69 6e 00 53 68 65 6c 6c 2e 45 78 70 6c 6f 72 65 72 2e 31 00 4d 6f 7a 69 6c 6c 61 2e 42 72 6f 77 73 65 72 2e 31 00 41 74 6c 41 78 47 65 74 43 6f 6e 74 72 6f 6c 00 41 74 6c 41 78 57 69 6e 49 6e 69 74 00 41 54 4c 2e 44 4c 4c}  //weight: 1, accuracy: High
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_5 = "ShellExecuteExA" ascii //weight: 1
        $x_1_6 = {46 53 54 53 57 20 00 4c 4c 44 54 20 00 4c 4c 44 54 20 77 6f 72 64 00 4c 4d 53 57 20 00 4c 4d 53 57 20 77 6f 72 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Small_IT_2147602091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Small.IT"
        threat_id = "2147602091"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "312"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "http://%s:%d/%d%04d" ascii //weight: 100
        $x_100_2 = "c:\\Program Files\\Internet Explorer\\%s" ascii //weight: 100
        $x_100_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c ?? 2e 65 78 65}  //weight: 100, accuracy: Low
        $x_10_4 = "Messenger" ascii //weight: 10
        $x_1_5 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_6 = "AdjustTokenPrivileges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Small_MC_2147602205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Small.MC"
        threat_id = "2147602205"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\sysmon.exe" ascii //weight: 10
        $x_10_2 = "www.ringz.org" ascii //weight: 10
        $x_10_3 = "backdoor written by" ascii //weight: 10
        $x_1_4 = "WSASocketA" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Small_CN_2147602410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Small.CN"
        threat_id = "2147602410"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A*\\AE:\\My Programs\\Trojans, PS,Hack , Crack\\Molela\\Molela 1.15 beta\\Server\\Project1.vbp" wide //weight: 1
        $x_1_2 = "set cd door closed" wide //weight: 1
        $x_1_3 = "RemPass+-=-+" wide //weight: 1
        $x_1_4 = "TurnOffFirewall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Small_BO_2147623054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Small.BO"
        threat_id = "2147623054"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 45 78 70 6f 72 74 00 69 6d 70 6f 72 74 66 75 6e 63 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 46 14 8b 4e 18 2b c7 83 c4 0c 83 f9 10 89 46 14 72 02 8b 1b c6 04 03 00 5b}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 10 00 00 25 00 f0 ff ff 50 6a 00 6a 04 (52|ff 35 ?? ?? ?? ??) ff 15 ?? ?? 00 10 8b cf c1 e9 0c 81 e1 ff 03 00 00 8b 0c 88 f7 c1 01 00 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Small_CG_2147624581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Small.CG"
        threat_id = "2147624581"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 73 72 73 73 2e 65 78 65 00 5c 00 6e 6f 74 69 66 69 79 00 76 69 63 74 75 6d 00 c7 e1 d6 cd ed c9 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 00 2e 64 6c 6c 00 67 65 6e 72 61 6c 00 64 6c 6c 69 6e 6b 65 72 00 45 78 70 6c 6f 72 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Small_VB_2147629507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Small.VB"
        threat_id = "2147629507"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TNSH20066600991-SQYPL" ascii //weight: 1
        $x_1_2 = {32 30 35 2e 32 30 39 2e 31 34 ?? 2e [0-10] 46 69 6e 69 73 68 65 64 [0-10] 4e 6f 20 52 65 63 6f 72 64 20 48 65 72 65 [0-5] 43 4d 44 20 47 45 54 50 48 50 55 52 4c}  //weight: 1, accuracy: Low
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 [0-5] 25 73 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Small_BP_2147642434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Small.BP"
        threat_id = "2147642434"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 50 69 64 3a 25 64 20 44 65 73 63 3a 20 25 73 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {78 53 6f 63 6b 65 74 00 76 53 6f 63 6b 65 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "Start Transmit (%s:%d <-> %s:%d) ......" ascii //weight: 1
        $x_1_4 = {5b 2d 5d 20 41 63 63 65 70 74 31 20 65 72 72 6f 72 2e 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {f7 d1 2b f9 8b d1 87 f7 c1 e9 02 8b c7 f3 a5 8b ca 83 e1 03 f3 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Small_BR_2147643385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Small.BR!dll"
        threat_id = "2147643385"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Network\\Connections\\pbk\\rasphone.pbk" ascii //weight: 10
        $x_10_2 = "[Print Screen]" ascii //weight: 10
        $x_10_3 = {d7 dc b4 c5 c5 cc bf d5 bc e4 ce aa 3a 25 31 30 2e 25 66 47 2c}  //weight: 10, accuracy: High
        $x_1_4 = "exe.cvseva" ascii //weight: 1
        $x_1_5 = "exe.psidhsa" ascii //weight: 1
        $x_1_6 = "exe.ccgva" ascii //weight: 1
        $x_1_7 = "exe.ssdb" ascii //weight: 1
        $x_1_8 = "exe.redips" ascii //weight: 1
        $x_1_9 = "exe.pva" ascii //weight: 1
        $x_1_10 = "exe.nrk23don" ascii //weight: 1
        $x_1_11 = "exe.lrtcodiwe" ascii //weight: 1
        $x_1_12 = "exe.dleihscm" ascii //weight: 1
        $x_1_13 = "exe.serifvap" ascii //weight: 1
        $x_1_14 = "exe.ppacc" ascii //weight: 1
        $x_1_15 = "exe.nomtnccp" ascii //weight: 1
        $x_1_16 = "exe.23mssf" ascii //weight: 1
        $x_1_17 = "exe.tratsvak" ascii //weight: 1
        $x_1_18 = "exe.iuge" ascii //weight: 1
        $x_1_19 = "exe.nomvar" ascii //weight: 1
        $x_1_20 = "exe.pxvrsvk" ascii //weight: 1
        $x_1_21 = "exe.tnegadb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 12 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Small_BR_2147643386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Small.BR"
        threat_id = "2147643386"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rising Update" ascii //weight: 1
        $x_1_2 = "%s\\%d_res.tmp" ascii //weight: 1
        $x_1_3 = "rundll32.exe \"C:\\Remoete.dll\" WWWW" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\BITS\\Parameters" ascii //weight: 1
        $x_1_5 = "Winds Update" ascii //weight: 1
        $x_1_6 = "taskkill /f /im KsafeTray.exe" ascii //weight: 1
        $x_1_7 = "360tray.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

