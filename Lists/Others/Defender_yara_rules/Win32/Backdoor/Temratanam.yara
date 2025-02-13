rule Backdoor_Win32_Temratanam_A_2147709079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Temratanam.A"
        threat_id = "2147709079"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Temratanam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "RE\\Google\\Chroimum" wide //weight: 4
        $x_4_2 = "TVRAT_FREE" wide //weight: 4
        $x_4_3 = {31 00 32 00 33 00 34 00 00 00 00 00 74 00 76 00 70 00 61 00 73 00 73 00 00 00}  //weight: 4, accuracy: High
        $x_4_4 = "_tvratfree" ascii //weight: 4
        $x_1_5 = "rmansys.ru" wide //weight: 1
        $x_1_6 = {54 65 61 6d 56 69 65 77 65 72 00 00 44 79 6e 47 61 74 65 49 6e 73 74 61 6e 63 65 4d 75 74 65 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

