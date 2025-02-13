rule HackTool_Win32_Sfind_J_2147602267_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Sfind.J"
        threat_id = "2147602267"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfind"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 64 64 72 65 73 73 2e 00 00 00 00 00 00 00 2d 70 00 00 20 00 00 00 43 4f 4d 4d 41 4e 44 3a 20 00 00 00 77 73 61 74 61 72 74 75 70 20 65 72 72 6f 72 00 00 00 00 00 20 2d 63 6f 64 65 72 65 64 20 31 39 32 2e 31 36}  //weight: 1, accuracy: High
        $x_1_2 = {00 20 2d 77 65 62 64 61 76 20 31 39 32 2e 31 36 38 2e 30 2e 31 20 31 39 32 2e 31 36 38 2e 30 2e 32 35 35 20 00}  //weight: 1, accuracy: High
        $x_1_3 = {6e 64 20 75 6e 69 63 6f 64 65 20 68 6f 6c 65 [0-8] 47 45 54 20 2f 73 63 72 69 70 74 73 2f 2e 2e 25 32 35 35 63 25 32 35 35 63 2e 2e 2f 77 69 6e 6e 74 2f 73 79 73 74 65 6d 33 32 2f 63 6d 64 2e 65 78 65 3f 2f 63 2b 64}  //weight: 1, accuracy: Low
        $x_1_4 = "/cgi-bin/sawmill5?rfcf+%22/etc/passwd%22+spbn+1,1,21,1,1,1,1" ascii //weight: 1
        $x_1_5 = "Modified Sfind" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

