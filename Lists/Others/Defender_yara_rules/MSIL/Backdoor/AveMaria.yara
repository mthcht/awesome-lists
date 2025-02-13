rule Backdoor_MSIL_AveMaria_NYK_2147828058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AveMaria.NYK!MTB"
        threat_id = "2147828058"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CMCeCtChCoCdC0CCCCCCCCC" wide //weight: 1
        $x_1_2 = "SdVbcskldfjp" wide //weight: 1
        $x_1_3 = "GetManifestResourceStream" wide //weight: 1
        $x_1_4 = "pjdfsgyufiujg" wide //weight: 1
        $x_1_5 = "xckjvbvigforg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

