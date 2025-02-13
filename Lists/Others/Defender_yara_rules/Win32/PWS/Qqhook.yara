rule PWS_Win32_Qqhook_A_2147583578_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Qqhook.gen!A"
        threat_id = "2147583578"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Qqhook"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "QQHook" ascii //weight: 3
        $x_3_2 = {4e 75 6d 62 65 72 3d 00 ff ff ff ff 0a 00 00 00 26 50 61 73 73 57 6f 72 64 3d 00 00 ff ff ff ff 04 00 00 00 26}  //weight: 3, accuracy: High
        $x_3_3 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 3
        $x_3_4 = "HookClass" ascii //weight: 3
        $x_1_5 = "qq.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Qqhook_B_2147601436_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Qqhook.gen!B"
        threat_id = "2147601436"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Qqhook"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {75 1a 6a 00 a1 ?? ?? ?? 00 50 b8 ?? ?? ?? 00 50 6a ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? 00 83 3d ?? ?? ?? 00 00 75 1a 6a 00 a1 ?? ?? ?? 00 50 b8 ?? ?? ?? 00 50 6a ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? 00 c3 07 00 83 3d ?? ?? ?? 00 00}  //weight: 8, accuracy: Low
        $x_5_2 = {53 56 57 8b fa 8b f0 8b c6 e8 ?? ?? ?? ?? 8b d8 eb 01 4b 85 db 7e 15 80 7c 1e ff 5c 74 0e 80 7c 1e ff 3a 74 07 80 7c 1e ff 2f 75 e6 57 8b c6 e8 ?? ?? ?? ?? 8b c8 2b cb 8d 53 01 8b c6 e8 ?? ?? ?? ?? 5f 5e 5b c3}  //weight: 5, accuracy: Low
        $x_1_3 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_4 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_2_5 = {48 6f 6f 6b 4f 66 66 00}  //weight: 2, accuracy: High
        $x_2_6 = "QQPWD" ascii //weight: 2
        $x_2_7 = {00 4e 75 6d 62 65 72 3d 00}  //weight: 2, accuracy: High
        $x_2_8 = {00 26 50 61 73 73 57 6f 72 64 3d 00}  //weight: 2, accuracy: High
        $x_2_9 = {00 26 49 50 3d 00}  //weight: 2, accuracy: High
        $x_2_10 = "QQHook" ascii //weight: 2
        $x_2_11 = "HookClass" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_8_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 4 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

