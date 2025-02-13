rule TrojanDropper_Win32_Zlob_2147594502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zlob"
        threat_id = "2147594502"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 63 73 76 00 26 fe 84 85 8d ff 6c 3d 73 68 62 26 73 75 62 95 63 d3 6e 5e 4c 68 18 42 17 3e 64}  //weight: 1, accuracy: High
        $x_1_2 = {12 d8 66 6f 2f 67 65 c2 75 70 64 85 2e 70 68 70}  //weight: 1, accuracy: High
        $x_1_3 = {45 6e 5a 50 18 7c c0 3e 47 65 72 9f 2e 44 4c 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Zlob_A_2147599596_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zlob.gen!A"
        threat_id = "2147599596"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 0a 64 65 6c 20 2f 46 20 2f 51 20 69 6d 65 78 2e 62 61 74}  //weight: 1, accuracy: High
        $x_1_2 = {69 6d 65 78 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 6d 65 78 2e 62 61 74 20 2f 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 6f 64 65 63 5c 69 6e 73 74 61 6c 6c 2e 69 63 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 69 6c 6c [0-3] 6f 70 65 6e [0-3] 70 61 74 68 [0-3] 74 6f [0-3] 74 68 65 [0-3] 70 72 6f 74 65 63 74 65 64 [0-3] 66 69 6c 65 73}  //weight: 1, accuracy: Low
        $x_1_6 = {2f 4e 65 77 4d 65 64 69 61 43 6f 64 65 63 2e 6f 63 78 00}  //weight: 1, accuracy: High
        $x_1_7 = "Nullsoft Install System" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

