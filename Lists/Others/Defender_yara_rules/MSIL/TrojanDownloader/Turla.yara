rule TrojanDownloader_MSIL_Turla_AF_2147982555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Turla.AF!AMTB"
        threat_id = "2147982555"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Turla"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://37.59.60.199/2018/.config/adobe" ascii //weight: 2
        $x_2_2 = "http://134.209.222.206:15363" ascii //weight: 2
        $x_1_3 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_4 = "set_UseShellExecute" ascii //weight: 1
        $x_1_5 = "ProcessStartInfo" ascii //weight: 1
        $x_1_6 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

