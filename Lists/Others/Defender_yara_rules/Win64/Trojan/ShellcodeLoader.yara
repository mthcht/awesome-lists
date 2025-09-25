rule Trojan_Win64_ShellcodeLoader_MKV_2147942741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.MKV!MTB"
        threat_id = "2147942741"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 1e 32 18 48 8b 95 58 02 00 00 48 83 ec 20 48 89 f9 e8 12 a3 00 00 48 83 c4 20 88 18 48 8b 9d ?? ?? ?? ?? 48 83 c3 01 b8 56 e9 d3 fd 3d e3 8d 0c 15 0f 8e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_AJZ_2147944327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.AJZ!MTB"
        threat_id = "2147944327"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 c8 49 f7 e0 48 c1 ea 03 48 8d 04 92 48 89 ca 48 01 c0 48 29 c2 41 0f b6 04 11 30 04 0e 48 83 c1 01 48 81 f9 00 02 00 00 75 d4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_NOV_2147950131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.NOV!MTB"
        threat_id = "2147950131"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 48 8b 4c 24 70 48 8b c1 48 8b 4c 24 78 48 f7 f1 48 8b c2 48 8d 0d 88 ed 00 00 0f be 04 01 48 8b 4c 24 30 48 8b 94 24 ?? ?? ?? ?? 0f b6 0c 11 33 c8 8b c1 48 63 4c 24 28 48 8b 54 24 30 88 04 0a e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_AN_2147952413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.AN!MTB"
        threat_id = "2147952413"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellcodeLoader" ascii //weight: 1
        $x_1_2 = "latestumang.netlify.app/shellcode.bin" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeLoader_TRX_2147953142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.TRX!MTB"
        threat_id = "2147953142"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 44 24 ?? 48 8d 8c 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 39 44 24 ?? 73 ?? 0f b6 05 ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 8b d0 48 8d 8c 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 44 24 ?? 48 8b 44 24 ?? 0f b6 00 88 44 24 ?? 0f b6 44 24 ?? 33 44 24 ?? 48 8b 4c 24 ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

