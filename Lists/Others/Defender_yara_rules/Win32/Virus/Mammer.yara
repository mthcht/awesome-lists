rule Virus_Win32_Mammer_A_2147682328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Mammer.A"
        threat_id = "2147682328"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Mammer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d b1 6b 8b fe 51 ad 92 ad 91 56 57 6a 20 5e b8 20 37 ef c6 ff d5 e8 24 00 00 00 2b cf 52 8b d1 ff d5 5a 2d b9 79 37 9e 8b d8 e8 15 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

