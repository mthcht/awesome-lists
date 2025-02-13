rule Backdoor_Win32_Isnup_A_2147616456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Isnup.A"
        threat_id = "2147616456"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Isnup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 84 81 00 00 00 56 6a 01 6a 25 8d 44 24 28 50 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {3c 3b 74 09 8a 44 1e 01 46 84 c0 75 f3}  //weight: 1, accuracy: High
        $x_1_3 = {85 ff b0 45 7e 14 56 8b 74 24 0c 30 04 31 2c 06 b2 14 f6 ea 41 3b cf 7c f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Isnup_B_2147622850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Isnup.B"
        threat_id = "2147622850"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Isnup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 3f 75 70 64 61 75 16 b8 74 65 00 00 66 39 47 04 75 0b}  //weight: 2, accuracy: High
        $x_2_2 = {3c 3b 74 08 46 8a 04 3e 84 c0 75 f4}  //weight: 2, accuracy: High
        $x_2_3 = {ff 45 fc 39 4d fc 7c e3 ff 45 f8 39 4d f8 7c d8 ff 45 f4}  //weight: 2, accuracy: High
        $x_2_4 = "id=%s&port=%d&isnat=%d&uptime=%d&ver=%d" ascii //weight: 2
        $x_1_5 = "Google bot" ascii //weight: 1
        $x_1_6 = "MsUpdater" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

