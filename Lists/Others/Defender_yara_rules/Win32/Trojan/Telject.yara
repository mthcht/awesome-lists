rule Trojan_Win32_Telject_A_2147690028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Telject.A"
        threat_id = "2147690028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Telject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c6 99 bb 0f 00 00 00 f7 fb 8a 01 8a 54 14 14 3a c2 74 ?? 32 c2 88 04 0f 46 41 3b f5 7c ?? 8b 54 24 10 c6 04 32 00}  //weight: 5, accuracy: Low
        $x_5_2 = {8b c6 99 bd 0f 00 00 00 f7 fd 8a 01 8a 54 14 14 3a c2 74 02 32 c2 88 04 0f 46 41 3b f3 7c e1}  //weight: 5, accuracy: High
        $x_5_3 = {8d 54 24 18 8b f0 e8 ?? ?? ?? ?? 8d 44 24 18 50 53 53 ff d6}  //weight: 5, accuracy: Low
        $x_5_4 = {85 c0 0f 84 80 00 00 00 8d 8c 24 60 01 00 00 8d 44 24 2c 8a 10 3a 11 75 1a 84 d2}  //weight: 5, accuracy: High
        $x_2_5 = "appfreetools.com " ascii //weight: 2
        $x_2_6 = "colorballsout.com" ascii //weight: 2
        $x_3_7 = "Support/libs/adslists.php" ascii //weight: 3
        $x_5_8 = "PInG     3.3.3.255 -w     2000   -n 1" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

