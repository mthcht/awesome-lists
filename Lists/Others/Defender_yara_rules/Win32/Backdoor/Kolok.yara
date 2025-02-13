rule Backdoor_Win32_Kolok_A_2147660361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kolok.A"
        threat_id = "2147660361"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 c9 85 d2 74 21 52 3a 0a 74 17 3a 4a 01 74 11 3a 4a 02 74 0b 3a 4a 03 74 05 83 c2 04 eb e8 42 42 42 89 d1 5a 29 d1 e9}  //weight: 2, accuracy: High
        $x_2_2 = {66 c7 43 04 20 03 66 c7 43 06 58 02 66 c7 43 08 4b 00 66 c7 43 0a 20 00 c6 43 0c 00 8d 43 10 ba ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_1_3 = "%2build=%1&version=2.0.Fix&connect=1" ascii //weight: 1
        $x_1_4 = "%vx%hx%bpp - %f" ascii //weight: 1
        $x_10_5 = {74 61 73 6b 6d 67 72 2e 65 78 65 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

