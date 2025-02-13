rule TrojanDropper_Win32_Malres_A_2147621371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Malres.A"
        threat_id = "2147621371"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Malres"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 00 00 53 74 61 72 74 00 00 00 45 72 72 6f 72 43 6f 6e 74 72 6f 6c 00 00 00 00 54 79 70 65 00 00 00 00 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 00 00 00 00 72 65 73 64 72 33 32 00 5c 64 72 69 76 65 72 73 5c 72 65 73 64 72 33 32 2e 73 79 73 00 00 00 00 5c 63 6f 6e 66 69 67 2e 64 61 74 00 53 79 73 74 65 6d 5c 43}  //weight: 1, accuracy: High
        $x_1_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 00 5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00 00 00 00 73 76 63 68 6f 73 74 2e 65 78 65 00 61 76 70 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

