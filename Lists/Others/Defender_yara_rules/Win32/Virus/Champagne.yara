rule Virus_Win32_Champagne_A_2147602085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Champagne.A"
        threat_id = "2147602085"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Champagne"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "with love /berniee" ascii //weight: 2
        $x_1_2 = "me3za.exe" ascii //weight: 1
        $x_1_3 = {73 6c 75 74 3f 21 21 00 41 64 64 53 65 63 74 69 6f 6e 2e 65 78 65 00 53 65 63 74 69 6f 6e 2e 65 78 65}  //weight: 1, accuracy: High
        $x_4_4 = {2a 2e 65 78 65 00 2e 2e 00 64 20 4d 20 79 00 54 6f 20 74 68 65 20 77 68 6f 6d 20 49 20 6c 6f 76 65 64 0d 0a 54 6f 20 74 68 65 20 77 68 6f 6d 20 49 20 6e 65 65 64 65 64 0d 0a 59 6f 75 20 77 65 72 65 20 74 68 65 20 6f 6e 6c 79 20 66 6f 74 75 6e 65 20 49 20 65 76 65 72}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

