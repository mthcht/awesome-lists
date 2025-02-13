rule Virus_Win32_Weird_F_2147546647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Weird.F"
        threat_id = "2147546647"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Weird"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 e8 00 00 00 00 5d 81 c5 03 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 00 2e 65 78 65 c6 40 04 00 33 d2 52 68 22 00 00 00 68 01 00 00 00 52 52 68 00 00 00 40 8d 85 ?? ?? ?? 00 50 ff 57 08 83 f8 ff 74 2b 8b d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

