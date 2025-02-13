rule Backdoor_Win32_Rashster_A_2147686580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rashster.gen!A"
        threat_id = "2147686580"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rashster"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {34 d7 88 04 11 41 3b ce 7c ef}  //weight: 3, accuracy: High
        $x_1_2 = {68 65 61 72 74 62 65 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 6d 64 73 68 65 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 35 63 35 33 65 73 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_5 = {61 50 33 6a 33 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

