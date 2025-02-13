rule TrojanDownloader_MSIL_ClipBanker_SK_2147753086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ClipBanker.SK!MTB"
        threat_id = "2147753086"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "https://vihanSoft.ir/d.zip" wide //weight: 10
        $x_1_2 = "Built-in account for administering the computer/domain" wide //weight: 1
        $x_1_3 = "SetPassword" wide //weight: 1
        $x_1_4 = "Finish extract" wide //weight: 1
        $x_5_5 = "\\DesktopService\\Windows Desktop Service.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_ClipBanker_RDA_2147837811_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ClipBanker.RDA!MTB"
        threat_id = "2147837811"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 91 20 64 03 00 00 59 d2 9c 00 06 17 58 0a}  //weight: 2, accuracy: High
        $x_1_2 = "om/attac" wide //weight: 1
        $x_1_3 = ".disco" wide //weight: 1
        $x_1_4 = "hments/927290247853772820/1031768209126342705/868" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

