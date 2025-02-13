rule TrojanDownloader_MSIL_Lowdanex_A_2147723074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lowdanex.A"
        threat_id = "2147723074"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lowdanex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.ictcoe.org.et/plugins/system/legacy/Vine.exe" wide //weight: 1
        $x_1_2 = "http://www.ictcoe.org.et/plugins/system/legacy/core.php" wide //weight: 1
        $x_1_3 = "DownloadAndExecute\\obj\\Release\\Download.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

