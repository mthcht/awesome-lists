rule Trojan_Win32_ShellCodeRunner_GNB_2147894388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellCodeRunner.GNB!MTB"
        threat_id = "2147894388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {30 04 3e 43 6a 00 ff 15 ?? ?? ?? ?? b8 cd cc cc cc f7 e6 c1 ea 02 8d 0c 92 8b d6 2b d1 75 02 33 db 46 81 fe 00 00 10 00 7c d0}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellCodeRunner_GPA_2147899027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellCodeRunner.GPA!MTB"
        threat_id = "2147899027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d7 8a 86 ?? ?? ?? ?? 2c 03 56 68}  //weight: 1, accuracy: Low
        $x_1_2 = "Executing shellcode" ascii //weight: 1
        $x_1_3 = "Shellcode execution complete" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellCodeRunner_NZL_2147942096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellCodeRunner.NZL!MTB"
        threat_id = "2147942096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c3 8b 5d f0 88 0c 3a 8b 55 e0 0f b6 0c 02 0f b6 04 3a 03 c8 83 7e ?? 0f 0f b6 c1 8b ce 89 45 ec 76}  //weight: 5, accuracy: Low
        $x_4_2 = {8a 0c 01 32 0c 16 8b 53 ?? 88 4d ff 3b 53 08 74}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellCodeRunner_KK_2147943867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellCodeRunner.KK!MTB"
        threat_id = "2147943867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {83 c0 23 6a 02 59 6b c9 2f 66 89 81 ?? ?? ?? ?? 6a 02 58 6b c0 2f 0f b7 80 ?? ?? ?? ?? 83 e8 07 6a 02 59 6b c9 30}  //weight: 20, accuracy: Low
        $x_10_2 = "yyxf_play.dll" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellCodeRunner_KK_2147943867_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellCodeRunner.KK!MTB"
        threat_id = "2147943867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 0a 8d 52 04 33 4a f8 81 e1 ff ff ff 7f 33 4a f8 8b c1 24 01 0f b6 c0 f7 d8 1b c0 d1 e9 25 df b0 08 99 33 82 2c 06 00 00 33 c1 89 82 b8 09 00 00 83 ef 01}  //weight: 3, accuracy: High
        $x_2_2 = {56 89 45 f0 89 55 f4 ff 15 ?? ?? ?? ?? 0f b7 c0 0f 57 c0 66 89 45 e8 40 66 89 45 ea 8d 45 f8}  //weight: 2, accuracy: Low
        $x_5_3 = {5c 00 62 00 75 00 69 00 6c 00 64 00 65 00 72 00 5f 00 76 00 [0-3] 5c 00 73 00 74 00 65 00 61 00 6c 00 63 00 5c 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

