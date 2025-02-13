rule TrojanDownloader_Win32_Syglor_A_2147648272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Syglor.A"
        threat_id = "2147648272"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Syglor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {be 0f 00 00 00 33 ff 52 89 b5 ?? ?? ?? ?? 89 bd ?? ?? ?? ?? c6 85 ?? ?? ?? ?? 00 e8}  //weight: 10, accuracy: Low
        $x_1_2 = "&hardid=%s" ascii //weight: 1
        $x_1_3 = "\\CurrentVersion\\Run]" ascii //weight: 1
        $x_1_4 = "User-Agent: Opera/9.80" ascii //weight: 1
        $x_1_5 = "95 OSR 2" ascii //weight: 1
        $x_1_6 = "123.tmp" ascii //weight: 1
        $x_1_7 = "/.sys.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

