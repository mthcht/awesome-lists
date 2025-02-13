rule Worm_Win32_Woriply_A_2147644890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Woriply.A"
        threat_id = "2147644890"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Woriply"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "regKey=1FGN-9DNN-2HLZ-L9MK-R8DH-I84J" ascii //weight: 10
        $x_1_2 = {6d 61 69 6e 63 6c 61 73 73 3d 6d 75 6c 74 69 70 6c 79 0a}  //weight: 1, accuracy: High
        $x_1_3 = {6d 61 69 6e 63 6c 61 73 73 3d 78 73 65 65 64 6d 61 69 6e 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Woriply_B_2147644891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Woriply.B"
        threat_id = "2147644891"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Woriply"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im mcvsshld.exe" ascii //weight: 1
        $x_1_2 = "attrib +h ftpcmds2.txt" ascii //weight: 1
        $x_1_3 = "ftp -s:ftpcmds.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Woriply_A_2147644902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Woriply.gen!A"
        threat_id = "2147644902"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Woriply"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "1FGN-9DNN-2HLZ-L9MK-R8DH-I84J" ascii //weight: 4
        $x_1_2 = {73 65 72 76 69 63 65 4e 61 6d 65 3d 73 76 63 61 67 65 6e 74 0a}  //weight: 1, accuracy: High
        $x_1_3 = {6d 61 69 6e 63 6c 61 73 73 3d 42 61 63 6b 75 70 4d 6f 6e 69 74 6f 72 0a}  //weight: 1, accuracy: High
        $x_2_4 = {6d 61 69 6e 63 6c 61 73 73 3d 6d 75 6c 74 69 70 6c 79 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

