rule Worm_Win32_Folmess_A_2147617433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Folmess.A"
        threat_id = "2147617433"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Folmess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\system32\\taskmdr.exe" ascii //weight: 1
        $x_1_2 = {5c 73 79 73 74 65 6d 33 32 5c 73 65 72 76 69 63 65 2e 65 78 65 00 00 00 4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 00 00 00 cf e0 ef ea e0 20 e8 ec e5 e5 f2 20 ed e5 e2 e5 f0 ed fb e9 20 f4 ee f0 ec e0 f2}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\Documents and Settings\\KAKTYC\\" ascii //weight: 1
        $x_1_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 ff ff ff ff 0f 00 00 00 57 69 6e 64 6f 77 73 53 65 72 76 69 63 65 73}  //weight: 1, accuracy: High
        $x_1_5 = {cd ee e2 e0 ff 20 ef e0 ef ea e0 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

