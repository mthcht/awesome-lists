rule Virus_Win32_Knat_2147609892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Knat"
        threat_id = "2147609892"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Knat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 46 08 28 31 9f 25 c7 46 58 00 00 00 00 0f b7 46 06 6b c0 28 8d bc 06 d0 00 00 00 6a 00 ff 75 dc e8 ?? ?? ?? 00 05 57 34 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 83 2c 24 7a 5d 68 00 10 00 00 e8 ?? ?? 00 00 0b c0 0f 84 ?? ?? 00 00 97 68 00 08 00 00 57 56 e8 ?? ?? 00 00 66 83 3f 00 0f 84 ?? ?? 00 00 50 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

