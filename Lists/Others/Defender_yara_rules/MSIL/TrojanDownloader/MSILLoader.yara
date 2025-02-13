rule TrojanDownloader_MSIL_MSILLoader_CSWF_2147845026_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/MSILLoader.CSWF!MTB"
        threat_id = "2147845026"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 06 91 15 2d 15 26 03 06 03 07 91 9c 03 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32}  //weight: 5, accuracy: High
        $x_1_2 = "http://downloadserver.duckdns.org/SystemEnv/uploads" wide //weight: 1
        $x_1_3 = "http://maloymez.beget.tech/panel/uploads/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

