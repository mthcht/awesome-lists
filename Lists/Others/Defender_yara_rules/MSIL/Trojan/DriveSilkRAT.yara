rule Trojan_MSIL_DriveSilkRAT_GX_2147976899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DriveSilkRAT.GX!MTB"
        threat_id = "2147976899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DriveSilkRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 0a 16 0b 16 13 05 2b 49 06 17 58 20 00 01 00 00 5d 0a 07 08 06 91 58 20 00 01 00 00 5d 0b 08 06 91 13 06 08 06 08 07 91 9c 08 07 11 06 9c 08 08 06 91 08 07 91 58 20 00 01 00 00 5d 91 13 07 09 11 05 02 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 11 05 02 8e 69 32 b0 09 2a}  //weight: 10, accuracy: High
        $x_5_2 = "Z2CbE1jLB41uOCmEfbmWlgEczd6M5" wide //weight: 5
        $x_1_3 = "Global\\TB_CS" ascii //weight: 1
        $x_1_4 = "DownloadFileAsync" ascii //weight: 1
        $x_1_5 = "GetMotherboardId" ascii //weight: 1
        $x_1_6 = "get_DangerousAcceptAnyServerCertificateValidator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

