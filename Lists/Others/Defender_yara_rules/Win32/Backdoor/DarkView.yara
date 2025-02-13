rule Backdoor_Win32_DarkView_A_2147599612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DarkView.A"
        threat_id = "2147599612"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkView"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "107"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {53 83 ec 20 89 e0 89 c2 83 c2 20 c7 00 00 00 00 00 83 c0 04 39 d0 75 f3 8b 54 24 28 8d 0c 24 e8 ?? ?? 00 00 c7 44 24 04 00 00 00 00 ff 34 24 e8 ?? ?? 00 00 89 c3 43 89 5c 24 08 ff 74 24 2c 68 00 00 00 00 68 ff 0f 1f 00 e8 ?? ?? 00 00 89 44 24 0c 83 7c 24 0c 00 0f 84 ?? ?? 00 00 68 04 00 00 00 68 00 10 00 00 ff 74 24 10 68 00 00 00 00 ff 74 24 1c}  //weight: 100, accuracy: Low
        $x_2_2 = {78 63 6f 6e 66 69 67 2e 73 72 76 00}  //weight: 2, accuracy: High
        $x_1_3 = {25 70 72 6f 67 72 61 6d 66 69 6c 65 73 25 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 64 65 73 6b 74 6f 70 25 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 6f 77 6e 64 61 74 61 25 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 79 73 74 65 6d 72 6f 6f 74 25 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 73 79 73 74 65 6d 33 32 25 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 53 68 65 6c 6c 5c 4f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_DarkView_B_2147642901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DarkView.B"
        threat_id = "2147642901"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkView"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Injected to: " ascii //weight: 2
        $x_4_2 = "\\xconfig.srv" ascii //weight: 4
        $x_3_3 = "[Shell already closed]" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

