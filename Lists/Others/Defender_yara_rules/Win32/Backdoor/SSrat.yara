rule Backdoor_Win32_SSrat_A_2147636973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/SSrat.A"
        threat_id = "2147636973"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "SSrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 35 74 46 40 00 e8 ae 1b 00 00 89 c3 83 fb ff 75 04 31 c0 eb 05 b8 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 49 4e 49 53 45 52 56 53 53 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 46 47 00 6f 70 65 6e 00 38 35 34 7c 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 69 6e 55 70 64 61 74 65 00 53 53 52 41 54}  //weight: 1, accuracy: High
        $x_1_5 = {77 69 6e 73 76 63 68 6f 73 74 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 52 75 6e 00 33 34 7c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

