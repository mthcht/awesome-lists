rule Worm_Win32_Emold_D_2147611299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Emold.gen!D"
        threat_id = "2147611299"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Emold"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {28 07 30 07 47 e2 f9 eb 0a 00 bf ?? ?? ?? ?? b9 ?? ?? 00 00}  //weight: 3, accuracy: Low
        $x_2_2 = {57 4e 44 43 4c 41 53 53 58 45 4d 4f 52 45 53 00}  //weight: 2, accuracy: High
        $x_1_3 = "/ld.php?v=1&" ascii //weight: 1
        $x_1_4 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 6f 74 65 70 61 64 20 77 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
        $x_1_6 = {31 6f 61 64 4c 69 62 72 61 72 79 41 00}  //weight: 1, accuracy: High
        $x_3_7 = {5b 61 75 74 6f 72 75 6e 5d 0d 0a 00}  //weight: 3, accuracy: High
        $x_3_8 = {6f 70 65 6e 3d 73 79 73 74 65 6d 2e 65 78 65 0d 0a 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

