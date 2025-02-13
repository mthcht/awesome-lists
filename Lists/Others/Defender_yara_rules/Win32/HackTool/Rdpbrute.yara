rule HackTool_Win32_Rdpbrute_2147648831_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Rdpbrute"
        threat_id = "2147648831"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rdpbrute"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DUBrute" ascii //weight: 1
        $x_1_2 = "http://ubrute.com" ascii //weight: 1
        $x_1_3 = "Crash... %s:%s:%s" ascii //weight: 1
        $x_1_4 = {5b 50 61 73 73 77 6f 72 64 5d 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 4c 6f 67 69 6e 5d 0a 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 64 2e 25 64 2e 25 64 2e 25 64 2d 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_Win32_Rdpbrute_B_2147648843_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Rdpbrute.gen!B"
        threat_id = "2147648843"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rdpbrute"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 4f 52 54 20 33 33 38 39 20 6f 70 65 6e 20 25 73 0a}  //weight: 2, accuracy: High
        $x_2_2 = "Found RDP %s" ascii //weight: 2
        $x_1_3 = {53 74 61 72 74 69 6e 67 20 66 74 70 20 62 72 75 74 65 20 25 73 0a}  //weight: 1, accuracy: High
        $x_1_4 = {44 69 61 70 61 73 6f 6e 20 44 61 74 61 20 73 65 6e 74 0a}  //weight: 1, accuracy: High
        $x_1_5 = {43 20 25 73 20 2d 20 25 73 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

