rule Backdoor_Win32_Rifelku_A_2147710561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rifelku.A"
        threat_id = "2147710561"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rifelku"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 ef 05 8b da c1 e3 04 33 fb 03 fa 8b d8 83 e3 03 8b 5c 9d ec 03 d8 33 fb 03 cf 2d 47 86 c8 61}  //weight: 1, accuracy: High
        $x_1_2 = {c1 ef 05 8b d9 c1 e3 04 33 fb 03 f9 8b d8 c1 eb 0b 83 e3 03}  //weight: 1, accuracy: High
        $x_1_3 = {c1 eb 18 32 1c 3e 89 55 e0 c1 ea 10 32 da 8b d1 c1 ea 18 32 da 8b 55 e0 c1 ea 08 32 da}  //weight: 1, accuracy: High
        $x_1_4 = "**Download Succ**" ascii //weight: 1
        $x_1_5 = "**Download Fail**" ascii //weight: 1
        $x_1_6 = "$download" ascii //weight: 1
        $x_1_7 = "sec.exe" ascii //weight: 1
        $x_1_8 = "$downloadexec" ascii //weight: 1
        $x_1_9 = "CMD:%s PROCESSED AT %d/%d/" ascii //weight: 1
        $x_1_10 = "sniffer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

