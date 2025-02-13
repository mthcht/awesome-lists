rule TrojanDropper_Win32_Relis_A_2147598031_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Relis.A"
        threat_id = "2147598031"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Relis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "122"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 00 00 10 00 00 00 72 00 65 00 6c 00 69 00 6e 00 73 00 6f 00 6e 00 00 00 00 00 3a 00 00 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 6e 00 6f 00 2e 00 65 00 78 00 65}  //weight: 100, accuracy: High
        $x_10_2 = {73 65 72 76 65 72 73 00 00 73 65 74 75 70}  //weight: 10, accuracy: High
        $x_10_3 = {4b 00 56 00 00 00 00 00 10 00 00 00 53 00 79 00 6d 00 61 00 6e 00 74 00 65 00 63 00}  //weight: 10, accuracy: High
        $x_1_4 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_5 = "RegSetValueExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

