rule Backdoor_Win32_Botintin_A_2147651686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Botintin.A"
        threat_id = "2147651686"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Botintin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Projects\\Infinity Bot\\" ascii //weight: 1
        $x_1_2 = {2f 50 61 6e 65 6c 2f 69 6e 66 2f 61 63 63 65 70 74 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = "&task=" ascii //weight: 1
        $x_1_4 = "&os=" ascii //weight: 1
        $x_1_5 = "&quality=" ascii //weight: 1
        $x_1_6 = "&computer=" ascii //weight: 1
        $x_1_7 = "&country=" ascii //weight: 1
        $x_1_8 = {3f 68 77 69 64 3d [0-2] 57 69 6e 64 6f 77 73 25 32 30 32 30 30 30 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

