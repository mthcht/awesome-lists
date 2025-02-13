rule Backdoor_Win32_Meciv_A_2147641564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Meciv.A"
        threat_id = "2147641564"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Meciv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 20 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 6e 65 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_3 = "/trandocs/netstat" ascii //weight: 2
        $x_1_4 = {65 6c 64 6e 61 48 65 73 6f 6c 43 74 65 6e 72 65 74 6e 49 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 79 73 33 32 74 69 6d 65 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 69 70 6f 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_7 = "/trandocs/mm/" ascii //weight: 2
        $x_1_8 = "felixnewly.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

