rule Trojan_Win32_Matanbuch_PA_2147904751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matanbuch.PA!MTB"
        threat_id = "2147904751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matanbuch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 08 8b 55 ?? 0f be 02 33 c8 66 89 8d ?? ?? ?? ?? 8b 4d ?? 8b 55 ?? 8d 44 4a 02 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 66 8b 95 ?? ?? ?? ?? 66 89 11 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

