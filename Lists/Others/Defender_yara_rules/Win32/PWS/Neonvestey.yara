rule PWS_Win32_Neonvestey_A_2147647893_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Neonvestey.A"
        threat_id = "2147647893"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Neonvestey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f be 0c 08 83 f1 71 88 0c 30 40 eb e9}  //weight: 2, accuracy: High
        $x_2_2 = {2a 00 2e 00 78 00 6c 00 73 00 2a 00 00 00 00 00 2a 00 2e 00 70 00 70 00 74 00 2a 00 00 00 00 00 2a 00 2e 00 74 00 78 00 74 00 00 00 2a 00 2e 00 70 00 68 00 70 00 2a 00}  //weight: 2, accuracy: High
        $x_2_3 = {43 6f 6c 6c 65 63 74 49 6e 66 6f 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_1_4 = {74 65 64 50 61 73 73 77 6f 72 64 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "= Firefox Username ==" wide //weight: 1
        $x_1_6 = "= Recent Application List ==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

