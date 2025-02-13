rule TrojanDownloader_MSIL_Controvant_A_2147695693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Controvant.A"
        threat_id = "2147695693"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Controvant"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL3Bhc3RlYmluLmNvbS9yYXcucGhwP" wide //weight: 1
        $x_1_2 = "Your computer not found of virus" wide //weight: 1
        $x_1_3 = "Antivirus 2015.exe" ascii //weight: 1
        $x_1_4 = "\\Hat Mast3r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

