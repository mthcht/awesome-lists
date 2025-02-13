rule TrojanDownloader_MSIL_Ranos_A_2147685690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Ranos.A"
        threat_id = "2147685690"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ranos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bankingcal.Resources" ascii //weight: 1
        $x_1_2 = "tnioPyrtnE" ascii //weight: 1
        $x_1_3 = "httpslogin" ascii //weight: 1
        $x_1_4 = "Now Executing Custom Application..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

