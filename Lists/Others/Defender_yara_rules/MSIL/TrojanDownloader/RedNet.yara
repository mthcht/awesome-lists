rule TrojanDownloader_MSIL_RedNet_CCJZ_2147943668_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedNet.CCJZ!MTB"
        threat_id = "2147943668"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedNet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "drive.google.com/uc?export=download&id=1dhE0aQd0kQwINIE88hHR58WKq2DfXbvL" wide //weight: 2
        $x_2_2 = "Fty4rBj9QYo=" wide //weight: 2
        $x_1_3 = "GZSckwNk3rQ5chMNbwafzg==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

