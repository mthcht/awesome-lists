rule PWS_Win32_Reder_B_2147653759_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Reder.B"
        threat_id = "2147653759"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Reder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b df 89 5d ?? 7d ?? 8b 45 ?? 8a 04 06 88 04 1e 68 ?? ?? ?? ?? 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 83 45 ?? 03 43 39 7d ?? 7c de}  //weight: 2, accuracy: Low
        $x_2_2 = {45 4d 41 49 4c 3a 20 25 73 0a 50 41 53 53 20 3a 20 25 73}  //weight: 2, accuracy: High
        $x_1_3 = "!tickit!" ascii //weight: 1
        $x_1_4 = "!block!" ascii //weight: 1
        $x_1_5 = "!screen!" ascii //weight: 1
        $x_1_6 = "!reder!" ascii //weight: 1
        $x_1_7 = "!kill!" ascii //weight: 1
        $x_1_8 = "220d5cc1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

