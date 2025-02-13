rule Backdoor_Win32_Meac_A_2147683679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Meac.A"
        threat_id = "2147683679"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Meac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "duq1" ascii //weight: 1
        $x_1_2 = "MyShell.lnk" wide //weight: 1
        $x_1_3 = "make a b c" ascii //weight: 1
        $x_1_4 = "\\SystemCFG.lnk" wide //weight: 1
        $x_4_5 = {25 73 20 23 32 00 00 00 33 36 30 74 72 61 79 2e 65 78 65}  //weight: 4, accuracy: High
        $x_4_6 = {4b 56 53 72 76 58 50 2e 65 78 65 00 73 79 73 74 65 6d 5c 66 78 73 73 74 2e 64 6c 6c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

