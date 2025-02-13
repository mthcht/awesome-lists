rule Trojan_Win32_Ditertag_A_2147722997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ditertag.A"
        threat_id = "2147722997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ditertag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SHCreateItemFromParsingName" ascii //weight: 3
        $x_3_2 = "ShellExecuteExW" ascii //weight: 3
        $x_3_3 = "\\sysprep\\sysprep.exe" ascii //weight: 3
        $x_3_4 = "Elevation:Administrator!" ascii //weight: 3
        $x_3_5 = "{3ad05575-8857-4850-9277-11b85bdb8e09}" ascii //weight: 3
        $x_3_6 = "EnableLUA" ascii //weight: 3
        $x_3_7 = "C:\\Windows\\SysEvent.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ditertag_MR_2147743825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ditertag.MR!MTB"
        threat_id = "2147743825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ditertag"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8b 55 ?? 03 55 f0 8b 45 ?? 8b 4d ?? 8a 0c 31 88 0c 10 8b 55 ?? 83 c2 ?? 89 55 ?? eb 27 00 b8 ?? ?? ?? ?? 85 c0 74 ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? 8b 75 ?? 03 75 ?? 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 0b 00 a1 ?? ?? ?? ?? 31 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ditertag_DSK_2147744216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ditertag.DSK!MTB"
        threat_id = "2147744216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ditertag"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d d0 89 c2 83 ca 01 d3 ff 0f af d1 03 7d 08 29 d0 03 45 08 8a 17 ff 4d ec 88 55 cf 8a 10 88 17 8a 55 cf 88 10 75}  //weight: 2, accuracy: High
        $x_2_2 = {8b 55 e0 89 54 24 04 e8 ?? ?? ?? ?? 89 f1 d3 ff 09 f0 03 45 08 03 7d 08 ff 4d e8 8a 08 8a 17 88 0f 88 10 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ditertag_RT_2147780298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ditertag.RT!MTB"
        threat_id = "2147780298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ditertag"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 db 81 c3 15 2f cc 6a 81 c3 78 4d a2 2c 31 0f 09 f6 81 c7 02 00 00 00 4e 81 eb 01 00 00 00 39 c7 7c 9f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

