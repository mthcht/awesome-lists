rule TrojanDownloader_WinCE_MobUn_A_2147643833_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:WinCE/MobUn.A"
        threat_id = "2147643833"
        type = "TrojanDownloader"
        platform = "WinCE: Windows CE platform"
        family = "MobUn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Windows\\msservice.exe" wide //weight: 1
        $x_1_2 = "\\Windows\\upd_msservice.exe" wide //weight: 1
        $x_1_3 = "http://mobileunit.ru/index.php?getstr=param" wide //weight: 1
        $x_1_4 = {5c 53 72 76 55 70 64 61 74 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

