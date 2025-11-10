rule Trojan_Win32_AuraStealer_GMT_2147957153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AuraStealer.GMT!MTB"
        threat_id = "2147957153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AuraStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 28 00 0f 57 02 31 c9 80 7e ?? 01 0f 29 00 89 46 ?? 0f 94 c1}  //weight: 5, accuracy: Low
        $x_5_2 = {0f 28 03 0f 57 00 0f 29 03 89 5e ?? 8b 46 ?? 80 38 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

