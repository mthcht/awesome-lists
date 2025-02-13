rule Backdoor_Win32_Mongall_MA_2147822277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mongall.MA!MTB"
        threat_id = "2147822277"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mongall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4c 24 7c 68 80 00 00 00 51 88 44 24 60 ff 15 ?? ?? ?? ?? 8d 54 24 7c 52 ff 15 ?? ?? ?? ?? 8b 40 0c 8b 08 8b 11 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 10 83 7d d0 ?? 74 ?? ff 75 d0 e8 ?? ?? ?? ?? 83 65 d0 ?? 59 8b 75 0c 8a 1e 46 84 db 89 75 0c 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = "somnuek.bu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mongall_MB_2147901451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mongall.MB!MTB"
        threat_id = "2147901451"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mongall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 84 24 44 01 00 00 83 e1 03 52 f3 a4 50 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "\\WINDOWS\\SYSTEM32\\netbridge.exe" ascii //weight: 1
        $x_1_4 = "ndbssh.com" ascii //weight: 1
        $x_1_5 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

