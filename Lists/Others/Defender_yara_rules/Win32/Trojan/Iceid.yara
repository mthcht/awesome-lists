rule Trojan_Win32_IceID_AD_2147742844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IceID.AD!MTB"
        threat_id = "2147742844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IceID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 2b ce 83 c1 04 0f b7 c9 89 4c 24 ?? 8d 8d ?? ?? ?? ?? 66 01 0d ?? ?? ?? ?? 8b 0a 81 fe ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 6b c0 ?? 2b de 83 c3 ?? 81 c1 ?? ?? ?? ?? 0f b7 db 89 0a 0f b7 2d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 0f b7 cb 2b c1 8d 98 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 03 c5 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IceID_GG_2147755510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IceID.GG!MTB"
        threat_id = "2147755510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IceID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fa 8d 84 3d [0-4] 8a 10 88 16 88 18 0f b6 [0-2] 0f b6 [0-2] 03 c2 99 8b f1 f7 fe 8b 85 [0-4] 8a 94 [0-5] 30 10 40 83 7d [0-2] 00 89 85 [0-4] 75 88 00 ff 4d [0-2] 40 33 d2}  //weight: 1, accuracy: Low
        $x_1_2 = "VirtualAllocExNuma" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IceID_SK_2147834140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IceID.SK!MTB"
        threat_id = "2147834140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IceID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZQtvzPWUYnoBRG" ascii //weight: 1
        $x_1_2 = "zEplQFmNPfboAthJ" ascii //weight: 1
        $x_1_3 = "STrsVmvBTjDgBYF" ascii //weight: 1
        $x_1_4 = "uasifbyugashfjakshbass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

