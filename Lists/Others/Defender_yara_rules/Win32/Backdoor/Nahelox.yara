rule Backdoor_Win32_Nahelox_A_2147646869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nahelox.A"
        threat_id = "2147646869"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nahelox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/c netsh firewall set opmode disable" wide //weight: 2
        $x_2_2 = "System32\\Helena\\" wide //weight: 2
        $x_2_3 = "win_s912" ascii //weight: 2
        $x_4_4 = {8b 45 fc 8b 80 8c 03 00 00 8b 80 a0 02 00 00 8b 55 fc 8b 92 9c 03 00 00 8b 08 ff 51 7c}  //weight: 4, accuracy: High
        $x_4_5 = {8b 45 f0 50 b8 ?? ?? 4b 00 89 45 f4 c6 45 f8 11 8d 45 f4 50 6a 00 b9 26 27 00 00 b2 01 a1 14 96 4b 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

