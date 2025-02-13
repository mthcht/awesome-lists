rule PWS_Win32_Hoppa_A_2147694400_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hoppa.A"
        threat_id = "2147694400"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hoppa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {5d 2e 74 78 74 00 00 00 18 00 5b 00 00 00 ff ff ff ff 02 00 00 00 5d 5b 00 00 ff ff ff ff 05 00 00 00}  //weight: 4, accuracy: Low
        $x_1_2 = {00 57 49 4e 44 4f 57 53 20 4c 49 56 45 20 4d 45 53 53 45 4e 47 45 52 20 50 41 53 53 57 4f 52 44 53 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 46 49 52 45 46 4f 58 20 20 50 41 53 53 57 4f 52 44 53 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 4f 4f 47 4c 45 20 43 48 52 4f 4d 45 20 50 41 53 53 57 4f 52 44 53 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 4f 50 45 52 41 20 50 41 53 53 57 4f 52 44 53 00}  //weight: 1, accuracy: High
        $x_4_6 = {00 57 69 6e 48 4e 00}  //weight: 4, accuracy: High
        $x_8_7 = {c6 80 84 00 00 00 75 c6 80 85 00 00 00 41 c6 80 86 00 00 00 8d c6 80 87 00 00 00 58 c6 80 88 00 00 00 04 c6 80 89 00 00 00 81 c6 80 8a 00 00 00 3b c6 80 8b 00 00 00 4c c6 80 8c 00 00 00 69 c6 80 8d 00 00 00 62 c6 80 8e 00 00 00 72}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

