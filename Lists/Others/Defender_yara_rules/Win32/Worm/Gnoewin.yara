rule Worm_Win32_Gnoewin_A_2147660174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gnoewin.A"
        threat_id = "2147660174"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gnoewin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".gonewiththewings" ascii //weight: 1
        $x_1_2 = {b9 3f 00 00 00 33 c0 8d 7c 24 14 8d 54 24 14 f3 ab 66 ab 8d 8c 24 40 01 00 00 51 52 aa ff d6 8d 44 24 14 68 ?? ?? ?? ?? 50 ff d3 8d 4c 24 14 6a 01 8d 94 24 44 01 00 00 51 52 ff d5 8d 44 24 14 68 80 00 00 00 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gnoewin_B_2147661150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gnoewin.B"
        threat_id = "2147661150"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gnoewin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 63 20 22 25 25 53 79 73 74 65 6d 52 6f 6f 74 25 25 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 25 25 63 64 25 25 25 73 20 26 20 73 74 61 72 74 20 25 25 63 64 25 25 25 73 20 26 20 65 78 69 74 22 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 5c 25 73 00 00 00 25 73 5c 25 73 2e 6c 6e 6b}  //weight: 1, accuracy: High
        $x_1_3 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 53 48 45 4c 4c 33 32 2e 64 6c 6c 00 00 00 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {24 14 c6 44 24 15 3a 88 5c 24 16 ff 15 ?? ?? ?? ?? 83 f8 02 0f 85 ?? 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

