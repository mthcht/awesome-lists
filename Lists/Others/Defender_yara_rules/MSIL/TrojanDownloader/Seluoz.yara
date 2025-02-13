rule TrojanDownloader_MSIL_Seluoz_A_2147685789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Seluoz.A"
        threat_id = "2147685789"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seluoz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "/run.php" wide //weight: 1
        $x_1_3 = "\\a.exe" wide //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
        $x_1_5 = "userandpc=" wide //weight: 1
        $x_1_6 = "dlurl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

