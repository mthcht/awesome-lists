rule Trojan_Win32_Katchlink_C_2147753442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Katchlink.C!dha"
        threat_id = "2147753442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Katchlink"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {77 69 6e 73 61 66 65 5f 33 32 2e 64 6c 6c 00 70 72 6f 74 65 63 74}  //weight: 3, accuracy: High
        $x_3_2 = {77 69 6e 73 61 66 65 5f 36 34 2e 64 6c 6c 00 70 72 6f 74 65 63 74}  //weight: 3, accuracy: High
        $x_1_3 = {47 6c 6f 62 61 6c 5c 77 6f 77 00}  //weight: 1, accuracy: High
        $x_1_4 = "open file error\\nerror code:%d" ascii //weight: 1
        $x_1_5 = "read lenth :%d,return value:%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

