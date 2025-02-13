rule Backdoor_Win32_Fastoh_A_2147685553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fastoh.A"
        threat_id = "2147685553"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fastoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 86 ac 00 00 00 b0 1b 88 44 24 04 88 44 24 05 88 44 24 06 88 44 24 07}  //weight: 1, accuracy: High
        $x_1_2 = {8d 86 b5 00 00 00 6a 00 50 ff d7 8b 8e a8 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {eb 07 8b 4e 0c 8b 11 8b 02 8b 95 a8 00 00 00 8d 4c 24 1c 6a 10 51 52 89 44 24 2c ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

