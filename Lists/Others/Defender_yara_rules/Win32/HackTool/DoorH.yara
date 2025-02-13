rule HackTool_Win32_DoorH_A_2147724633_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DoorH.A!dha"
        threat_id = "2147724633"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DoorH"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 65 6e 75 6d 0a 00 45 6e 75 6d 20 74 68 65 20 48 6f 73 74 5c 55 73 65 72 5c 47 72 6f 75 70}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 66 70 6f 72 74 09 00 46 70 6f 72 74}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 68 62 73 0b 00 50 6f 72 74 20 42 61 6e 6e 65 72 20 53 63 61 6e 6e 65 72}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 68 73 63 61 6e 09 00 50 69 6e 67 2f 4e 61 6d 65 2f 53 51 4c 2f 49 50 43 20 53 63 61 6e 6e 65 72}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 50 61 63 6b 65 74 08 00 50 61 63 6b 65 74 20 54 72 61 6e 73 6d 69 74}  //weight: 1, accuracy: Low
        $x_1_6 = {2d 70 75 6c 69 73 74 08 00 4c 69 6b 65 20 50 75 6c 69 73 74}  //weight: 1, accuracy: Low
        $x_1_7 = {2d 70 73 6b 69 6c 6c 08 00 4b 69 6c 6c 20 61 20 50 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
        $x_1_8 = {2d 70 73 6c 69 73 74 08 00 4c 69 73 74 20 50 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
        $x_1_9 = {2d 73 61 66 65 64 65 6c 07 00 53 61 66 65 20 44 65 6c 65 74 65 20 46 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_10 = "-setfiletime   Set File Time" ascii //weight: 1
        $x_1_11 = {2d 73 6f 63 6b 73 09 00 53 6f 63 6b 73 35 20 50 72 6f 78 79}  //weight: 1, accuracy: Low
        $x_1_12 = {2d 73 71 6c 0b 00 53 51 4c 20 78 70 5f 63 6d 64 73 68 65 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

