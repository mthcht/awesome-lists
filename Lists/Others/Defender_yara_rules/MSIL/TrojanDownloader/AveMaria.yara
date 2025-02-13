rule TrojanDownloader_MSIL_AveMaria_RDB_2147849606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AveMaria.RDB!MTB"
        threat_id = "2147849606"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c68a3983-587d-4e5f-ad53-9a8b83c05c14" ascii //weight: 1
        $x_1_2 = "spb-gan.ru/panel/uploads/Hzbdzjo.png" wide //weight: 1
        $x_1_3 = "Ilyobdvhnnpqgkinvofkc.Ofiejkodfyng" wide //weight: 1
        $x_1_4 = "Ahyfeinbtxue" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

