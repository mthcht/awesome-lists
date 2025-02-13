rule TrojanDownloader_MSIL_Lakusaup_A_2147697256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lakusaup.A"
        threat_id = "2147697256"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lakusaup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sugarsync.com/pf/D" wide //weight: 1
        $x_1_2 = "?directDownload=true" wide //weight: 1
        $x_1_3 = "Users\\eCoLoGy\\Documents" ascii //weight: 1
        $x_1_4 = "\\xupaeu.exe" wide //weight: 1
        $x_1_5 = "\\adbupdate.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

