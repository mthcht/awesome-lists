rule Ransom_Win32_SamSam_SA_2147934119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SamSam.SA"
        threat_id = "2147934119"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SamSam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\\\tsclient\\" wide //weight: 10
        $x_100_2 = {5c 00 2e 00 6d 00 63 00 5f 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 100, accuracy: Low
        $x_100_3 = {5c 00 6d 00 63 00 5f 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 100, accuracy: Low
        $x_1_4 = "\\kali\\" wide //weight: 1
        $x_1_5 = "\\kalilinux\\" wide //weight: 1
        $x_1_6 = "\\pencha\\" wide //weight: 1
        $x_1_7 = "\\sila\\" wide //weight: 1
        $x_1_8 = "\\pendekar\\" wide //weight: 1
        $x_1_9 = "\\pende5\\" wide //weight: 1
        $x_1_10 = "\\b\\sqll" wide //weight: 1
        $x_1_11 = "\\b\\admin" wide //weight: 1
        $x_1_12 = "\\b\\sql" wide //weight: 1
        $x_1_13 = "\\b\\01" wide //weight: 1
        $x_1_14 = "\\b\\1" wide //weight: 1
        $x_1_15 = "\\b\\bug\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 11 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

