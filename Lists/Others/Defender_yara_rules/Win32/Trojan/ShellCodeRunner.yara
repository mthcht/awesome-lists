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

