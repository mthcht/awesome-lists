rule TrojanDropper_Win32_Goriadu_A_2147709216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Goriadu.A!bit"
        threat_id = "2147709216"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Goriadu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 00 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 00 00 72 00 73 00 74 00 72 00 61 00 79 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 4c 00 6f 00 67 00 46 00 69 00 6c 00 65 00 73 00 00 00 25 00 73 00 5c 00 53 00 4e 00 31 00 5f 00 25 00 64 00 5f 00 25 00 64 00 2e 00 6c 00 6f 00 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 00 00 4e 00 6f 00 52 00 75 00 6e 00 00 00 4e 00 6f 00 44 00 72 00 69 00 76 00 65 00 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 6b 28 57 0d 59 36 52 87 65 f6 4e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

