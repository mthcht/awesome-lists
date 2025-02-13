rule HackTool_Win32_Noposel_A_2147726688_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Noposel.A"
        threat_id = "2147726688"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Noposel"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 70 73 2e 65 78 65 00 50 72 6f 67 72 61 6d 00 6e 70 73 00 6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 4d 61 69 6e 00 2e 63 74 6f 72 00 61 72 67 73 00 53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 00 41 73 73 65 6d 62 6c 79 54 69 74 6c 65 41 74 74 72 69 62 75 74 65 00 41 73 73 65 6d 62 6c 79 44 65 73 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

