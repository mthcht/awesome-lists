rule TrojanDownloader_MSIL_Gabrenehu_A_2147694468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gabrenehu.A"
        threat_id = "2147694468"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gabrenehu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "/inhaltsangaben.eu/wp-content/" wide //weight: 4
        $x_4_2 = "wp-content/plugins/xml/2012100.zip" wide //weight: 4
        $x_2_3 = "fucker0202#" wide //weight: 2
        $x_2_4 = "flash.zip" wide //weight: 2
        $x_1_5 = "senhadozip" ascii //weight: 1
        $x_1_6 = "nomedozip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

