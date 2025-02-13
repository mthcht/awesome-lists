rule TrojanDropper_Win32_Pabat_A_2147643132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pabat.A"
        threat_id = "2147643132"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pabat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 65 6c 20 22 43 3a 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 62 6f 6f 74 63 66 67 2e 65 78 65 22 20 2f 46 20 2f 53 20 2f 51 0d 0a 6d 73 67 20 2a 20 4c 4f 4c}  //weight: 1, accuracy: High
        $x_1_2 = {6d 73 67 20 2a 20 4c 4f 4c 0d 0a 73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 20 31 30 30 20 2d 63 20 22 56 49 52 55 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

