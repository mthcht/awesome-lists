rule TrojanSpy_Win32_Roscamoin_A_2147691435_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Roscamoin.A"
        threat_id = "2147691435"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Roscamoin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "w.rscamnl.com/d/get_keys.php?keys_pressed=" ascii //weight: 4
        $x_4_2 = "\\good keylogger\\" wide //weight: 4
        $x_4_3 = "198.173.124.107/d/get_keys.php" wide //weight: 4
        $x_2_4 = "keys_pressed=" wide //weight: 2
        $x_1_5 = "Install_flash_player" ascii //weight: 1
        $x_1_6 = "Required Key Strokes :" ascii //weight: 1
        $x_1_7 = "Victim Name :" ascii //weight: 1
        $x_1_8 = "get_dir_list_win7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

