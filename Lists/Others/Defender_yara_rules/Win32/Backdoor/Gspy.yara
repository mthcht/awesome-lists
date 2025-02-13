rule Backdoor_Win32_Gspy_A_2147651512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Gspy.A"
        threat_id = "2147651512"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Gspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OWN-BOT-ID" wide //weight: 2
        $x_2_2 = "PR_Write" ascii //weight: 2
        $x_2_3 = "injector" ascii //weight: 2
        $x_1_4 = "screenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Gspy_B_2147666754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Gspy.B"
        threat_id = "2147666754"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Gspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "420"
        strings_accuracy = "High"
    strings:
        $x_300_1 = {00 00 67 00 73 00 70 00 79 00 5f 00 62 00 6f 00 74 00 6e 00 65 00 74 00 00 00}  //weight: 300, accuracy: High
        $x_100_2 = "UNKNOWN-BOT-ID" wide //weight: 100
        $x_100_3 = {81 e7 ff 00 00 00 0f b6 1c 07 88 1c 02 88 0c 07 02 cb 0f b6 c9 8a 0c 01 30 0c 2e 46 89 7c 24 18 89 5c 24 10 3b 74 24 1c 72 c4}  //weight: 100, accuracy: High
        $x_40_4 = {7c 02 33 ff 0f b6 14 06 0f b6 1c 2f 03 da 03 cb 81 e1 ff 00 00 00 8a 1c 01 88 1c 06 47 4e 88 14 01 79 d6}  //weight: 40, accuracy: High
        $x_40_5 = "pe_injector_lock" ascii //weight: 40
        $x_40_6 = "bot_exclusive_lock" ascii //weight: 40
        $x_40_7 = {65 72 72 2d 34 00 00 00 6e 6f 74 20 69 6d 70 6c 65 6d 65 6e 74 65 64}  //weight: 40, accuracy: High
        $x_40_8 = "screenshots_by_request\\screenshot.jpg" wide //weight: 40
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_300_*) and 3 of ($x_40_*))) or
            ((1 of ($x_300_*) and 1 of ($x_100_*) and 1 of ($x_40_*))) or
            ((1 of ($x_300_*) and 2 of ($x_100_*))) or
            (all of ($x*))
        )
}

