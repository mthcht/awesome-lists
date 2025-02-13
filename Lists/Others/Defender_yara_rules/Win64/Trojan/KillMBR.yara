rule Trojan_Win64_KillMBR_RPJ_2147838256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillMBR.RPJ!MTB"
        threat_id = "2147838256"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 6d 1d 00 00 48 63 c3 f0 80 34 38 23 ff c3 81 fb ff 01 00 00 72 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillMBR_RPX_2147846027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillMBR.RPX!MTB"
        threat_id = "2147846027"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.f" ascii //weight: 1
        $x_1_2 = "%/nobreak   /C  timeout 1 &     move " ascii //weight: 1
        $x_1_3 = "Untitled.cvs" ascii //weight: 1
        $x_1_4 = "dir  & ver & tree &  erase   /f   /q" ascii //weight: 1
        $x_1_5 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_6 = "ll.df" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillMBR_EM_2147847658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillMBR.EM!MTB"
        threat_id = "2147847658"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/killwindows" ascii //weight: 1
        $x_1_2 = "/KillHardDisk" ascii //weight: 1
        $x_1_3 = "/killMBR" ascii //weight: 1
        $x_1_4 = "/autoup" ascii //weight: 1
        $x_1_5 = "Super-Virus" ascii //weight: 1
        $x_1_6 = "Cacls C:\\windows\\system32\\taskmgr.exe /t /e /c /g" ascii //weight: 1
        $x_1_7 = "I am virus! Fuck you" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillMBR_EM_2147847658_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillMBR.EM!MTB"
        threat_id = "2147847658"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cacls C:\\windows\\system32\\taskmgr.exe /t /e /c /g" ascii //weight: 1
        $x_1_2 = "/killwindows" ascii //weight: 1
        $x_1_3 = "/KillHardDisk" ascii //weight: 1
        $x_1_4 = "/killMBR" ascii //weight: 1
        $x_1_5 = "I am virus! Fuck you :-)" ascii //weight: 1
        $x_1_6 = "taskkill /f /im explorer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillMBR_ARA_2147914690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillMBR.ARA!MTB"
        threat_id = "2147914690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\cmd.exe /c echo y| format c: /fs:NTFS /q" ascii //weight: 2
        $x_2_2 = "\\\\.\\PhysicalDrive0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillMBR_ARA_2147914690_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillMBR.ARA!MTB"
        threat_id = "2147914690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Start reg delete HKCR/*" ascii //weight: 2
        $x_2_2 = "taskkill /f /fi \"pid ne 1" ascii //weight: 2
        $x_2_3 = "\\\\.\\PhysicalDrive0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_KillMBR_NM_2147917704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KillMBR.NM!MTB"
        threat_id = "2147917704"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KillMBR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {41 83 fe 01 75 ?? 8b 45 40 ff c8 48 89 1d cf 80 01 00 89 05 c5 80 01 00 eb ?? 48 8d 55 38 48 89 7d 38 48 8b cb}  //weight: 3, accuracy: Low
        $x_1_2 = "APM 08279+5255.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

