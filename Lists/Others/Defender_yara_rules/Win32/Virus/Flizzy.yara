rule Virus_Win32_Flizzy_A_2147656958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Flizzy.A"
        threat_id = "2147656958"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Flizzy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5e 8b 7b 08 b9 95 00 00 00 56 8b d4 ad 8d 2c 07 c8 04 00 02 83 c4 08 8f 46 fc e2 f0 8b e2 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

