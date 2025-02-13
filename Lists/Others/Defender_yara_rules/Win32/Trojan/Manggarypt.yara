rule Trojan_Win32_Manggarypt_B_2147725643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Manggarypt.B!bit"
        threat_id = "2147725643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Manggarypt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 8d 0c 37 99 f7 7d ?? 8a 44 15 ?? 32 04 19 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 00 00 00 80 73 ?? 83 c0 02 03 c3 eb ?? 0f b7 c0 50 ff 75 ?? ff 15 ?? ?? ?? ?? 89 04 37 83 c6 04 8b 06}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 11 8d 42 ?? 3c 19 77 03 80 c2 e0 88 11 41 80 39 00 75 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

