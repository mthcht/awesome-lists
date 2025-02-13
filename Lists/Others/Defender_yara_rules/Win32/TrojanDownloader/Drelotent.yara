rule TrojanDownloader_Win32_Drelotent_A_2147720999_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drelotent.A"
        threat_id = "2147720999"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drelotent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://unisdr.top/mail/index.php?id=" ascii //weight: 1
        $x_1_2 = "://corpconor-daily.pw/mail/index.php?id=" ascii //weight: 1
        $x_1_3 = "://sorrycorpmail.site/mail/index.php?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

