rule PWS_Win32_Nemim_A_2147679797_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Nemim.A"
        threat_id = "2147679797"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 44 24 08 6a 33 8d 4c 24 0c b2 52 50 51 c6 44 24 14 1e}  //weight: 1, accuracy: High
        $x_1_2 = {b8 56 55 55 55 8d 0c bd 00 00 00 00 f7 e9 8b c2 c1 e8 1f 8d 4c 02 04 51 e8}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 18 33 f6 33 ff 83 fe 10 7d 23 33 c0 8d}  //weight: 1, accuracy: High
        $x_1_4 = {a1 60 f3 82 00 83 f8 01 0f 8f 7a 05 00 00 85 c0 0f 85 c3 00 00 00 8b}  //weight: 1, accuracy: High
        $x_1_5 = {2f 68 74 6d 6c 2f 64 6f 63 75 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

