rule Backdoor_Win32_Faitypelf_A_2147621485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Faitypelf.A"
        threat_id = "2147621485"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Faitypelf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 68 34 02 00 00 50 8d 94 3e 34 02 00 00 56 55 89 54 24 40 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b 31 80 3e 2d 0f 84}  //weight: 1, accuracy: High
        $x_1_3 = "[msnbot]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Faitypelf_B_2147629962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Faitypelf.B"
        threat_id = "2147629962"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Faitypelf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 6d 73 6e 62 6f 74 5d 20 2d 20 74 68 65 20 70 72 6f 67 72 61 6d 28 25 73 29 20 68 61 73 20 62 65 65 6e 20 72 75 6e 6e 65 64 2c 50 49 44 3d 30 78 25 78 21 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {2d 75 73 65 72 20 00 00 2d 77 61 69 74 20 00 00 2d 63 68 65 63 6b 20 00 2d 68 69 64 65 20 00 00 66 61 69 6c 65 64 20 74 6f 20 66 69 6e 64 20 70 61 73 73 77 6f 72 64 20 28 25 53 2f 25 53 29 20 69 6e 20 6d 65 6d 6f 72 79 21 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 6e 61 62 6c 65 20 74 6f 20 6c 69 73 74 65 6e 20 73 6f 63 6b 65 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 74 a9 04 80 3e 2d 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

