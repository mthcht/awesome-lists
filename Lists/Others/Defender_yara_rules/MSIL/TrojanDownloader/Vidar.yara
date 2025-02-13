rule TrojanDownloader_MSIL_Vidar_RDC_2147838559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Vidar.RDC!MTB"
        threat_id = "2147838559"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "d1cc2bad-d6f7-47b8-afa8-3a9d4430dcc1" ascii //weight: 1
        $x_1_2 = "YJ234j8hTZD59PoO" ascii //weight: 1
        $x_1_3 = "IDpD0KK69V9p12ie" ascii //weight: 1
        $x_2_4 = {11 0d 11 10 1f 0f 5f 11 0d 11 10 1f 0f 5f 95 11 06 25 1a 58 13 06 4b 61 20 ?? ?? ?? ?? 58 9e 11 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Vidar_A_2147839043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Vidar.A!MTB"
        threat_id = "2147839043"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {94 58 18 28 ?? 00 00 06 5d 94 13 06 11 0a 11 04 07 11 04 91 11 06 61 d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Vidar_C_2147892366_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Vidar.C!MTB"
        threat_id = "2147892366"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "//tiny.one/bdhsxhu9" wide //weight: 5
        $x_1_2 = "GDdhjdrVe" ascii //weight: 1
        $x_1_3 = "Fcmhetf" ascii //weight: 1
        $x_1_4 = "ConcatState" ascii //weight: 1
        $x_1_5 = "GetResponseStream" ascii //weight: 1
        $x_1_6 = "Form1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

