rule Trojan_Win64_Mimikatz_D_2147829739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mimikatz.D!MSR"
        threat_id = "2147829739"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start gg.lnk" ascii //weight: 1
        $x_1_2 = "sekurlsa::logonpasswords" ascii //weight: 1
        $x_1_3 = "start procdump.exe -accepteula -ma lsass.exe lsass.dmp" ascii //weight: 1
        $x_1_4 = "expand mim mimi.exe" ascii //weight: 1
        $x_1_5 = "mimi.exestop" ascii //weight: 1
        $x_1_6 = "shaykhelislamov/Documents/Codetest/testproject/main/exec.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mimikatz_RPZ_2147902279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mimikatz.RPZ!MTB"
        threat_id = "2147902279"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 89 c6 48 89 7c 24 40 48 89 74 24 48 48 63 70 3c 8b 54 30 50 31 c9 41 b8 00 30 00 00 41 b9 04 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mimikatz_AMCV_2147928847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mimikatz.AMCV!MTB"
        threat_id = "2147928847"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {65 00 50 00 c7 85 ?? ?? 00 00 72 00 69 00 c7 85 ?? ?? 00 00 76 00 69 00 c7 85 ?? ?? 00 00 6c 00 65 00 c7 85 ?? ?? 00 00 67 00 65 00 c7 85 ?? ?? 00 00 20 00 28 00 c7 85 ?? ?? 00 00 25 00 73 00}  //weight: 4, accuracy: Low
        $x_4_2 = {41 0f b6 c1 8a 4c 04 20 88 4c 14 20 0f b6 45 21 41 03 c8 44 88 44 04 20 0f b6 c1 8a 4c 04 20 8a 45 20 30 0e fe c0 48 ff c6 88 45 20 49 3b f2}  //weight: 4, accuracy: High
        $x_1_3 = "cmd.exe /V:on /C reg delete HKLM\\Software\\CommandTmp /f" ascii //weight: 1
        $x_1_4 = "Please input ip. eg, /ip:xx.XXX.xx.x or /ip:xxx.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mimikatz_AHB_2147952646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mimikatz.AHB!MTB"
        threat_id = "2147952646"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {4c 89 6c 24 68 c6 44 24 3f 00 c6 44 24 3e 00 48 c7 44 24 50 00 00 00 00 c7 04 24 00 00 00 00 48 8d 54 24 50 48 89 54 24 08}  //weight: 20, accuracy: High
        $x_30_2 = {0f b6 34 10 4c 8d 42 01 4c 8d 8a ?? ?? ?? ?? 49 0f af f1 48 01 f1 4c 89 c2 48 39 d3 7f}  //weight: 30, accuracy: Low
        $x_10_3 = "spread.Cryptohijack" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

