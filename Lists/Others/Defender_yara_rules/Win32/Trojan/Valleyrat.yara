rule Trojan_Win32_Valleyrat_2147975348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valleyrat.MTSK!MTB"
        threat_id = "2147975348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valleyrat"
        severity = "Critical"
        info = "MTSK: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 03 55 fc 0f b6 02 0f b6 4d 10 33 c1 8b 55 14 03 55 fc 88 02 eb d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Valleyrat_YBA_2147976165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valleyrat.YBA!MTB"
        threat_id = "2147976165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valleyrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f3 0f 6f 00 66 0f 7f 84 24 ?? ?? ?? ?? 66 0f 6f 84 24 ?? ?? ?? ?? 66 0f ef 84 24 ?? ?? ?? ?? 66 0f 7f 84 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 66 0f 6f 84 24 ?? ?? ?? ?? f3 0f 7f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

