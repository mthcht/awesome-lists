rule Backdoor_Win32_Binanen_A_2147646989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Binanen.A!dll"
        threat_id = "2147646989"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Binanen"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 54 24 08 33 c0 85 d2 7e 17 8b 4c 24 04 53 8a 1c 08 80 f3 aa 88 1c 08 40 3b c2 7c f2 33 c0 5b}  //weight: 10, accuracy: High
        $x_1_2 = {63 6d 64 00 67 65 74 69 6e 66 6f 00 6c 69 73 74 64 69 73 6b}  //weight: 1, accuracy: High
        $x_1_3 = {48 6f 73 74 4e 61 6d 65 3a 25 73 20 20 55 73 65 72 4e 61 6d 65 3a 25 73 20 23 23 25 73 20 0d 0a 4f 70 65 6e 54 69 6d 65 3a 25 64 44 61 79 20 25 64 3a 25 64 20 20 20 20 4c 6f 63 61 6c 54 69 6d 65 3a 5b 25 30 32 64}  //weight: 1, accuracy: High
        $x_1_4 = {53 65 74 20 42 61 63 6b 20 44 61 74 65 74 69 6d 65 20 45 72 72 6f 72 21 00 00 00 30 53 65 74 20 42 61 63 6b 20 44 61 74 65 74 69 6d 65 20 4f 6b 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

