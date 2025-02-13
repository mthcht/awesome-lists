rule Virus_Win32_Triusor_2147707229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Triusor!dam"
        threat_id = "2147707229"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Triusor"
        severity = "Critical"
        info = "dam: damaged malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d bc 24 85 00 00 00 88 9c 24 84 00 00 00 68 00 04 00 00 f3 ab 66 ab aa 8d 84 24 88 00 00 00 c7 44 24 1c 00 00 00 00 50 53 89 5c 24 20 ff 15 ?? ?? ?? ?? 68 04 01 00 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d 8c 24 84 00 00 00 51 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 48 3c 03 c8 89 0d ?? ?? ?? ?? 81 39 50 45 00 00 0f 85 ?? ?? ?? ?? 33 d2 55 66 8b 51 14 56 8b f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

