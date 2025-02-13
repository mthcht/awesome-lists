rule Trojan_Win32_Unruy_GZZ_2147905544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Unruy.GZZ!MTB"
        threat_id = "2147905544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 0a 47 18 3a c8 04 08 64 46 34 fc ea ?? ?? ?? ?? 44 0e ee d2 75 14}  //weight: 5, accuracy: Low
        $x_5_2 = {ba 05 ac 3d 5c 30 10 40 49 0f 85}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Unruy_GZY_2147905790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Unruy.GZY!MTB"
        threat_id = "2147905790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0e 34 6b c0 12 fc 4e 46 09 27}  //weight: 5, accuracy: High
        $x_5_2 = {8a 66 7b f3 91 ba ?? ?? ?? ?? 34 e9 13 26 01 56 7b 1b 70 71 30 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Unruy_GZX_2147905821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Unruy.GZX!MTB"
        threat_id = "2147905821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 96 1a 01 01 b9 ?? ?? ?? ?? 67 bf ?? ?? ?? ?? 12 8a ?? ?? ?? ?? a3 ?? ?? ?? ?? 6d ?? 32 27 64 e0 f9 34 f4 ?? 01 5c 51 4f 14 7c 0d ?? ?? ?? ?? 4f 87 61 83}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

