rule Virus_Win32_Deelae_A_2147647372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Deelae.A"
        threat_id = "2147647372"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Deelae"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 ff 32 64 89 22 e8 00 00 00 00 f9 19 34 24 64 ad 8b 40 0c 8b 70 1c ad 8b 68 08 e8 20 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

