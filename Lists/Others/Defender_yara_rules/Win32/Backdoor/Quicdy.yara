rule Backdoor_Win32_Quicdy_A_2147724930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Quicdy.A"
        threat_id = "2147724930"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Quicdy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 00 2d 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 2d 00 68 00 74 00 74 00 70 00 32 00 20 00 2d 00 2d 00 75 00 73 00 65 00 2d 00 73 00 70 00 64 00 79 00 3d 00 6f 00 66 00 66 00 20 00 2d 00 2d 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 2d 00 71 00 75 00 69 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5f 77 76 3d 25 6c 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 63 30 30 35 39 35 34 34 30 65 38 30 31 66 38 61 35 64 32 61 32 61 64 31 33 62 39 37 39 31 62 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 de d1 89 b2 6a 08}  //weight: 1, accuracy: High
        $x_1_5 = {81 f1 ac 02 00 00 3b c1 75 14 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

