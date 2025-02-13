rule Trojan_Win32_GreenMach_2147811716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GreenMach.gen!dha"
        threat_id = "2147811716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GreenMach"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 7d 08 00 00 10 00 7c 07 b8 08 00 00 00 eb ?? 8b 45 fc 83 38 00 74 ?? 8b 4d fc 8b 11 89 55 f8 8b 45 f8}  //weight: 5, accuracy: Low
        $x_5_2 = {b9 a0 00 00 00 66 89 8d ?? ?? ?? ?? 33 d2 66 89 95 ?? ?? ?? ?? 6a 08 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

