rule Trojan_Win32_Satacom_2147781209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Satacom!MSR"
        threat_id = "2147781209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c start /B powershell -windowstyle hidden -command" ascii //weight: 1
        $x_5_2 = "//435464.com/" ascii //weight: 5
        $x_5_3 = "Software\\fuckyou\\" ascii //weight: 5
        $x_1_4 = "cmd /C regsvr32 /s \"%s\"" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Satacom_RPJ_2147835527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Satacom.RPJ!MTB"
        threat_id = "2147835527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d a0 8b 34 37 c1 ee 08 33 d6 8b 75 a0 8b 34 06 03 f2 8b 45 98 33 d2 f7 b5 68 ff ff ff 8b 45 0c 03 34 90 03 75 98 8b 55 a0 8b 04 0a 2b c6 89 85 64 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Satacom_RPK_2147835528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Satacom.RPK!MTB"
        threat_id = "2147835528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4d c3 80 c1 01 88 4d c3 0f be 55 c3 83 fa 40 7d 1a 0f be 45 c3 0f be 88 ?? ?? ?? ?? 8b 55 08 03 55 b0 0f be 02 3b c8 74 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Satacom_RPL_2147835529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Satacom.RPL!MTB"
        threat_id = "2147835529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4d ff 80 c1 01 88 4d ff 0f be 55 ff 83 fa 40 7d 1a 0f be 45 ff 0f be 88 ?? ?? ?? ?? 8b 55 08 03 55 e4 0f be 02 3b c8 74 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Satacom_MB_2147835530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Satacom.MB!MTB"
        threat_id = "2147835530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f be 44 15 f4 c1 f8 04 8d 0c 88 8b 55 ec 03 55 f8 88 0a 8b 45 f8 83 c0 01 89 45 f8 b9 01 00 00 00 d1 e1 0f be 54 0d f4 83 fa 40 0f 84 a0 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Satacom_RJ_2147835814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Satacom.RJ!MTB"
        threat_id = "2147835814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 06 c1 e8 08 33 d0 8b 45 fc 8b 0c 08 03 ca 8b 45 f8 33 d2 f7 75 f0 8b 45 10 03 0c 90 03 4d f8 ba 04 00 00 00 d1 e2 8b 45 fc 8b 14 10 2b d1 89 55 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Satacom_MA_2147835826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Satacom.MA!MTB"
        threat_id = "2147835826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "fork10.dll" ascii //weight: 10
        $x_1_2 = "WriteFile" ascii //weight: 1
        $x_1_3 = "SetThreadPriority" ascii //weight: 1
        $x_1_4 = "GetTickCount64" ascii //weight: 1
        $x_1_5 = "CreateEventA" ascii //weight: 1
        $x_1_6 = "OpenThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Satacom_RPT_2147836274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Satacom.RPT!MTB"
        threat_id = "2147836274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 fc c7 45 e0 25 06 00 00 c7 45 dc d4 e1 00 00 c7 45 d8 00 3e 00 00 c7 45 d4 24 06 00 00 c7 45 f0 04 00 00 00 c7 45 d0 81 68 02 00 c7 45 cc 23 df 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Satacom_A_2147946836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Satacom.A"
        threat_id = "2147946836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe c2 0f b6 d2 8b 4c ?? ?? 8d 04 0b 0f b6 d8 8b 44 ?? ?? 89 44 ?? ?? 89 4c ?? ?? 02 c8 0f b6 c1 8b 4d f8 8a 44 ?? ?? 30 04 ?? ?? 3b ?? fc 7c d0}  //weight: 2, accuracy: Low
        $x_1_2 = "|PIPE|vbOX" ascii //weight: 1
        $x_1_3 = {25 73 5c 73 76 63 68 6f 73 74 2e 25 73 [0-16] 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_4 = "crypto_domain" ascii //weight: 1
        $x_1_5 = "postback_url" ascii //weight: 1
        $x_1_6 = "execute_method" ascii //weight: 1
        $x_1_7 = "need_captcha" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

