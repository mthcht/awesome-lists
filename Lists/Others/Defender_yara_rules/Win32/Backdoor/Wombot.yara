rule Backdoor_Win32_Wombot_A_2147650360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wombot.A"
        threat_id = "2147650360"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wombot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 6f 74 6c 6f 67 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 77 6d 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 69 6e 5f 63 61 70 74 63 68 61 73 69 7a 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

