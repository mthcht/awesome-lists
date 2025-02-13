rule TrojanDropper_Win32_Protux_A_2147628666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Protux.A"
        threat_id = "2147628666"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Protux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 52 65 67 69 73 74 72 79 5c 4d 61 63 68 69 6e 65 5c 53 79 73 74 65 6d 5c 4e 4f 44 33 32 4c 65 61 64 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 52 65 67 69 73 74 72 79 5c 4d 61 63 68 69 6e 65 5c 53 4f 46 54 57 41 52 45 5c 4e 6f 64 33 32 41 6e 64 52 75 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 20 25 73 20 31 00 25 73 20 25 73 20 30 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 54 53 74 61 72 74 55 70 20 30 78 31 31}  //weight: 1, accuracy: High
        $x_1_4 = {5c 68 6f 6e 67 00 00 00 68 6f 6e 67 7a 69 6e 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Protux_B_2147645446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Protux.B"
        threat_id = "2147645446"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Protux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 43 52 65 73 74 61 72 74 20 30 78 31 31 00}  //weight: 10, accuracy: High
        $x_10_2 = {5c 68 6f 6e 00 00 00 00 68 6f 6e 67 7a 69 6e 73 74 00}  //weight: 10, accuracy: High
        $x_1_3 = {52 65 67 53 65 25 74 56 61 6c 75 65 45 23 78 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 65 67 51 24 75 65 72 79 56 61 6c 75 25 65 45 78 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Protux_B_2147645446_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Protux.B"
        threat_id = "2147645446"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Protux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 59 53 54 45 4d 5c 43 25 73 25 73 25 73 5c 50 61 72 61 6d 65 74 65 72 73 00 00 00 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 00 00 00 00 76 69 63 65 73 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 20 25 73 20 30 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 43 52 65 73 74 61 72 74 20 30 78 31 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 68 6f 6e 00 00 00 00 68 6f 6e 67 7a 69 6e 73 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

