rule TrojanDownloader_Win32_Anadeenfly_A_2147684223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Anadeenfly.A"
        threat_id = "2147684223"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Anadeenfly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NattlyDownload\\release\\NattlyDownload.pdb" ascii //weight: 1
        $x_1_2 = "coinis.com/getfileinstall.php" wide //weight: 1
        $x_1_3 = "NattlyDefender.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

