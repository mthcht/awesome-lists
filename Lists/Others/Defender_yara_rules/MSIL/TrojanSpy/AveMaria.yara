rule TrojanSpy_MSIL_AveMaria_2147820421_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/AveMaria!MTB"
        threat_id = "2147820421"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0c 04 00 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 91 fe ?? ?? 00 61 d2 9c 00 fe ?? ?? 00 20 ?? ?? ?? 00 58 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 8e 69 fe ?? fe ?? ?? 00 fe ?? ?? 00 3a ?? ?? ff ff}  //weight: 6, accuracy: Low
        $x_1_2 = "ToString" ascii //weight: 1
        $x_1_3 = "localFilePath" ascii //weight: 1
        $x_1_4 = "GetTempPath" ascii //weight: 1
        $x_1_5 = "ExtractResourceToRootPath" ascii //weight: 1
        $x_1_6 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

