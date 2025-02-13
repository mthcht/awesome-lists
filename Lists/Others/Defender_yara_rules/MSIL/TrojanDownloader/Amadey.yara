rule TrojanDownloader_MSIL_Amadey_RDA_2147841236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Amadey.RDA!MTB"
        threat_id = "2147841236"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "34effa55-c05e-4280-81b4-6b7a21d06d16" ascii //weight: 1
        $x_1_2 = "Seil" ascii //weight: 1
        $x_1_3 = "//valorantcheatsboss.com/upload/" wide //weight: 1
        $x_2_4 = {11 04 91 20 28 03 00 00 59 d2 9c 00 11 04 17 58 13 04 11 04 7e ?? ?? ?? ?? 8e 69 fe 04 13 05 11 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

