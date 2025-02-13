rule Trojan_Win32_KpotStealer_DHA_2147755513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KpotStealer.DHA!MTB"
        threat_id = "2147755513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KpotStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 4b fd ff ff 8b 4c 24 04 30 04 0e b8 01 00 00 00 83 f0 04 83 6c 24 04 01 83 7c 24 04 00 7d}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f b6 80 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 25 ff 00 00 00 81 3d ?? ?? ?? ?? 21 06 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KpotStealer_DHB_2147755647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KpotStealer.DHB!MTB"
        threat_id = "2147755647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KpotStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 f7 75 0c 8b 45 08 0f b6 0c 10 8b 55 10 03 55 fc 0f b6 02 33 c1 8b 4d 10 03 4d fc 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

