rule PWS_Win32_Cuepilini_A_2147652431_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cuepilini.A"
        threat_id = "2147652431"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cuepilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 8d 7d a0 f3 a5 8d 85 8c fa ff ff 66 a5 50 8d 85 98 fd ff ff 50 a4 ff}  //weight: 1, accuracy: High
        $x_1_2 = "nzzv<//www0" ascii //weight: 1
        $x_1_3 = {64 33 64 38 64 32 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 73 44 66 33 48 6a 38 6c 70 6f 76 78 58 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 73 74 72 50 61 73 73 77 6f 72 64 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 74 72 4c 65 66 74 50 77 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = {56 33 4c 52 75 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {4e 73 61 76 73 76 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_9 = "%*[^=]=%[^&]" ascii //weight: 1
        $x_1_10 = {64 66 6c 6f 67 69 6e 3d 00}  //weight: 1, accuracy: High
        $x_1_11 = "l_pwd=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

