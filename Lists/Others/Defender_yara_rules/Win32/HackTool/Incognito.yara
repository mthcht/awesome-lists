rule HackTool_Win32_Incognito_2147661227_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Incognito"
        threat_id = "2147661227"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Incognito"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 2a 5d 20 41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 61 64 64 20 75 73 65 72 20 25 73 20 74 6f 20 67 72 6f 75 70 20 25 73 20 6f 6e 20 64 6f 6d 61 69 6e 20 63 6f 6e 74 72 6f 6c 6c 65 72 20 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 2b 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 61 64 64 65 64 20 75 73 65 72 20 74 6f 20 67 72 6f 75 70 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = "incognito" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

