rule Worm_Win32_Otwycal_A_2147606451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Otwycal.gen!A"
        threat_id = "2147606451"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Otwycal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe ac 26 00 00 7f 23 83 f8 63 7f 1e 80 f9 2a 75 08}  //weight: 1, accuracy: High
        $x_1_2 = {2e c6 84 24 ?? ?? 00 00 65 c6 84 24 ?? ?? 00 00 78 c6 84 24 ?? ?? 00 00 74 88 84 24 ?? ?? 00 00 c6 84 24 ?? ?? 00 00 64 c6 84 24 ?? ?? 00 00 6f c6 84 24 ?? ?? 00 00 77 c6 84 24 ?? ?? 00 00 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

