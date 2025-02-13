rule TrojanDownloader_Win32_Macanscab_A_2147639539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Macanscab.A"
        threat_id = "2147639539"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Macanscab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/images/hotmail/mac.php" ascii //weight: 1
        $x_1_2 = "user_pref(\"network.proxy.autoconfig_url\", \"http:" ascii //weight: 1
        $x_1_3 = "svsinit.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

