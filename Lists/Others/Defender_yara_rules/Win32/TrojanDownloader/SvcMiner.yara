rule TrojanDownloader_Win32_SvcMiner_A_2147721292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/SvcMiner.A"
        threat_id = "2147721292"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "SvcMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "link-to-updated-file" wide //weight: 1
        $x_1_2 = "_update_ok.exe" wide //weight: 1
        $x_1_3 = "nointet_mi" wide //weight: 1
        $x_1_4 = "link-to-run-file" wide //weight: 1
        $x_1_5 = "command-to-run-file" wide //weight: 1
        $x_1_6 = "link-to-place-file" wide //weight: 1
        $x_1_7 = "feewallet" wide //weight: 1
        $x_1_8 = "Erase /F /A [SH] \"%s\"" wide //weight: 1
        $x_1_9 = "nofiles_ru" wide //weight: 1
        $x_1_10 = "nopools_ru" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

