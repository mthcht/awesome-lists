rule TrojanDownloader_Win32_Filachaem_A_2147599604_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Filachaem.A"
        threat_id = "2147599604"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Filachaem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://musah.info/" ascii //weight: 1
        $x_1_2 = "getconf.php" ascii //weight: 1
        $x_1_3 = "down_1_file: !fila net! - kachaem url=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

