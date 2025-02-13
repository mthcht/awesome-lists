rule PWS_Win32_Chif_A_2147626271_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Chif.A"
        threat_id = "2147626271"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Chif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 73 65 72 00 50 61 73 73 00 66 74 70 3a 2f 2f 00 3a 00 40 00 63 68 69 67 00 41 63 63 65 70 74 3a 20 2a 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 3b 50 61 73 73 75 ee 83 c3 04 8d bd b8 fd ff ff 43 66 81 3b 3c 2f 74 0a 8a 03 88 07 47 c6 07 00 eb ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

