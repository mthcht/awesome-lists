rule Backdoor_Win32_NetWolf_A_2147641102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetWolf.A"
        threat_id = "2147641102"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWolf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0c 06 80 f1 43 88 08 40 4f 75 f4}  //weight: 2, accuracy: High
        $x_1_2 = {8b 41 04 89 42 04 8b 41 08 89 42 08 8b 49 0c 89 4a 0c 8b 53 20}  //weight: 1, accuracy: High
        $x_1_3 = "-Svr [list] | [[info] | [start|stop|delete|restart]" ascii //weight: 1
        $x_1_4 = {2d 73 65 74 20 4d 61 69 6c 09 6d 61 69 6c 20 20 70 61 73 73 77 6f 72 64}  //weight: 1, accuracy: High
        $x_1_5 = {2d 73 65 74 20 48 74 74 70 50 72 6f 78 79 09 69 70 20 70 6f 72 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

