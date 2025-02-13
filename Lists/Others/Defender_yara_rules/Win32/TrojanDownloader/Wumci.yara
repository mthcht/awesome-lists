rule TrojanDownloader_Win32_Wumci_A_2147600063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wumci.A"
        threat_id = "2147600063"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wumci"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "HKCU^software\\xflock" ascii //weight: 3
        $x_3_2 = {68 02 00 00 80 68 ?? ?? 40 00 ff 35 ?? ?? ?? 00 c3}  //weight: 3, accuracy: Low
        $x_2_3 = {66 33 c9 8b 4d}  //weight: 2, accuracy: High
        $x_2_4 = {32 ed 8b 4d}  //weight: 2, accuracy: High
        $x_2_5 = {62 74 73 00}  //weight: 2, accuracy: High
        $x_1_6 = "ChkDsk32" ascii //weight: 1
        $x_1_7 = "http://getyouneed.com/r.php?wm=" ascii //weight: 1
        $x_1_8 = "getsoft.php?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

