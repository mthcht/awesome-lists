rule Trojan_Win32_Spystealer_VZ_2147819903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spystealer.VZ!MTB"
        threat_id = "2147819903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spystealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d8 31 d2 8d 8d ?? ?? ?? ?? f7 75 14 8b 45 08 0f be 34 10 e8 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 69 c6 ?? ?? ?? ?? 30 04 1f 43 eb}  //weight: 10, accuracy: Low
        $x_10_2 = {2e 00 00 00 c7 44 24 ?? 00 ac 01 00 c7 44 24 ?? 20 c0 4b 00 c7 04 24 ?? ?? ?? ?? 89 85 54 ff ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

