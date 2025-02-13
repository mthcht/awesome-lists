rule TrojanDropper_Win32_Phinit_B_2147628495_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Phinit.B"
        threat_id = "2147628495"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Phinit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 4d 65 73 73 65 6e 67 65 72 00 49 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 76 73 79 73 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 79 73 76 63 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 69 65 78 70 6c 6f 72 65 72 2e 65 78 65 22 20 48 45 4c 4c 4f 5f 45 37 38 34 38 46 42 42 2d 38 33 31 45 2d 34 33 61 34 2d 41 45 45 45 2d 37 31 43 30 41 33 43 35 32 45 45 41 5f 53 50 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

