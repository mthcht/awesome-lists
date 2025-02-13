rule TrojanDownloader_MSIL_Nomquoad_A_2147706034_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Nomquoad.A"
        threat_id = "2147706034"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nomquoad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.esaof.edu.pt/templates/beez/images_general/xml/xiqueyhayudhxzzc.exe" wide //weight: 1
        $x_1_2 = "nomar.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

