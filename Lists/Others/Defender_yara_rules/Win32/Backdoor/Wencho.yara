rule Backdoor_Win32_Wencho_A_2147707113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wencho.A"
        threat_id = "2147707113"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wencho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 69 6e 65 63 68 6f 2e 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 20 00 00 00 22 00 00 00 2f 63 20 63 6f 70 79 20 22 00 00 00 5c 74 61 73 6b 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "/c powershell -nop -win hidden -noni -enc JAAxACAAPQAgACcAJABjACAAPQAgACcAJwBbAEQAbABsAEkAbQBwAG" ascii //weight: 1
        $x_1_3 = "AAwACwAMAB4ADUANgAsADAAeAA1ADMALAAwAHgANQA3ACwAMAB4ADYAOAAsADAAeAAwADIALAAwAHgAZAA5ACwAMAB4AGMAOAAsADAAeAA1AGYALAAwAHgAZgBmACwAMAB4AGQANQAsADAAeAAwADEALAAwAHgAYwAzACwAMAB4ADIAOQAsADAAeABjADYALAAwAHgAOAA1ACwAM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

