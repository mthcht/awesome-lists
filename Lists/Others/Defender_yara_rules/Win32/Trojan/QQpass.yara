rule Trojan_Win32_QQpass_U_2147609539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQpass.U"
        threat_id = "2147609539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 da 32 1c 07 80 f3 80 46 88 18 c6 04 01 00 40 3b f5 7c d7}  //weight: 1, accuracy: High
        $x_1_2 = {99 b9 0a 00 00 00 f7 f9 80 c2 30 88 54 34 10 46 83 fe 05 7c e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QQpass_AY_2147634543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQpass.AY"
        threat_id = "2147634543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/lin.asp?A=%s&B=%s&" ascii //weight: 2
        $x_1_2 = "SYSTEM32\\tsscafe.dll" ascii //weight: 1
        $x_2_3 = "pobao/GetTuPian.asp" ascii //weight: 2
        $x_1_4 = "dNfcHiNa.Exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QQpass_E_2147635914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQpass.gen!E"
        threat_id = "2147635914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im QQ" ascii //weight: 1
        $x_1_2 = "\\Bin\\qqdat.exe" ascii //weight: 1
        $x_2_3 = "&qqpassword=" ascii //weight: 2
        $x_1_4 = "/START QQUIN" ascii //weight: 1
        $x_2_5 = {eb 12 83 e8 05 f7 d8 1b c0 83 e0 02 83 c0 04}  //weight: 2, accuracy: High
        $x_1_6 = "LoginUinList.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QQpass_CX_2147641878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQpass.CX"
        threat_id = "2147641878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a3 51 51 4d 67 73 be ee 39 49 7d 0b 72 ca 03 29 01 03 66 b0 41 9a 16}  //weight: 1, accuracy: High
        $x_1_2 = "1, 55, 1861, 0" wide //weight: 1
        $x_1_3 = {00 65 33 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = "TXProxy.GetProxyDllInfo" ascii //weight: 1
        $x_1_5 = "http\\shell\\open\\command\\" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\TENCENT\\QQ2009\\Install" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_QQpass_FZ_2147680070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQpass.FZ"
        threat_id = "2147680070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 54 24 10 8b 4c 24 08 30 14 08 40 3b c6 7c f8}  //weight: 1, accuracy: High
        $x_1_2 = "senddata.asp?1=abcdefg&2=1234567&3=" ascii //weight: 1
        $x_1_3 = {48 65 6e 77 61 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 58 47 75 69 46 6f 75 6e 64 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QQpass_EC_2147896930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQpass.EC!MTB"
        threat_id = "2147896930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JKJTrWGq23azWSDZw67q" ascii //weight: 1
        $x_1_2 = "KLJEWERHsdwqeh23211!@asdqSADwe" ascii //weight: 1
        $x_1_3 = "BRESUZCDY.jpg" ascii //weight: 1
        $x_1_4 = "ReadProcessMemory" ascii //weight: 1
        $x_1_5 = "online.de/home/Ollydbg" ascii //weight: 1
        $x_1_6 = "CreateThread" ascii //weight: 1
        $x_1_7 = "NtResumeProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QQpass_MX_2147931475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQpass.MX!MTB"
        threat_id = "2147931475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 fc 00 8b b5 dc fd ff ff 83 c6 f0 8d 7e 0c 83 c4 08 83 3f 00 8b d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QQpass_AB_2147952695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQpass.AB!MTB"
        threat_id = "2147952695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c9 ff 33 c0 f2 ae f7 d1 2b f9 68 00 18 00 00 8b c1 8b f7 8b fa 83 cb ff c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

