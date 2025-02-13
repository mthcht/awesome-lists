rule TrojanDownloader_MSIL_Nekozillot_A_2147725219_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Nekozillot.A!bit"
        threat_id = "2147725219"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekozillot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zillot.kz/System" wide //weight: 1
        $x_1_2 = "zillot_neko" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

