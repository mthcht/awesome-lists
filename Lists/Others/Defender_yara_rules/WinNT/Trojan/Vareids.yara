rule Trojan_WinNT_Vareids_A_2147628232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Vareids.A"
        threat_id = "2147628232"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Vareids"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {38 58 05 75 15 ff 77 10 ff 77 0c e8 ?? ?? ?? ?? c7 46 0c 34 00 00 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {10 83 66 10 00 6a 04 c7 46 0c 22 00 00 c0 58 eb 03}  //weight: 2, accuracy: High
        $x_2_3 = {8b 45 f0 8b 04 82 03 45 08 eb ee}  //weight: 2, accuracy: High
        $x_3_4 = "aqmgu" wide //weight: 3
        $x_1_5 = "msvcx86" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

