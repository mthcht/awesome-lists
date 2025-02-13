rule Backdoor_Win32_Sality_A_2147602871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sality.A"
        threat_id = "2147602871"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 02 7e 4b 8a 85}  //weight: 1, accuracy: High
        $x_3_2 = {25 ff 00 00 00 8b 8d ?? ?? ?? ff 81 e1 ff 00 00 00 0f af c1 05 38 04 00 00 66 a3}  //weight: 3, accuracy: Low
        $x_2_3 = {8b 55 08 66 c7 42 06 1e 00 8b 45 08 c7 40 08 3d 00 00 00 6a 3d 68}  //weight: 2, accuracy: High
        $x_2_4 = "&%x=%d&id=%d" ascii //weight: 2
        $x_1_5 = "%s:*:Enabled:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

