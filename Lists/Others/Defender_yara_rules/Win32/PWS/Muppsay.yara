rule PWS_Win32_Muppsay_B_2147626216_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Muppsay.B"
        threat_id = "2147626216"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Muppsay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 11 81 fa b8 00 00 00 74 04 33 c0 eb 1d}  //weight: 1, accuracy: High
        $x_1_2 = {60 b8 44 33 22 11 ff d0 61 68 78 56 34 12 c3}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d 08 8b 55 0c 89 51 02 8b 45 08 8b 4d 10 89 48 0a 5d c2 0c 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\SystemRoot\\temp\\system.bin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

