rule Backdoor_Win32_Quisbot_A_2147678406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Quisbot.A"
        threat_id = "2147678406"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Quisbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {42 6f 74 20 69 64 3a 20 25 73 0a 00 2f 73 00}  //weight: 2, accuracy: High
        $x_1_2 = {50 61 72 61 6d 3a 20 2f 73 74 61 72 74 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 75 70 64 61 74 65 2e 70 68 70 3f 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {0a 53 42 4f 54 20 73 74 61 72 74 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 25 73 5c 25 73 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

