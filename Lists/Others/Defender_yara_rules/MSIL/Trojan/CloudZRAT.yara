rule Trojan_MSIL_CloudZRAT_DA_2147968539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CloudZRAT.DA!MTB"
        threat_id = "2147968539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CloudZRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 08 18 5a 18 6f ?? ?? ?? 0a 0d 06 08 09 1f 10 28 ?? ?? ?? 0a 9c 06 08 8f ?? ?? ?? 01 25 47 07 61 d2 52 00 08 17 58 0c 08 06 8e 69 fe 04 13 04 11 04 2d cb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CloudZRAT_DB_2147968540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CloudZRAT.DB!MTB"
        threat_id = "2147968540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CloudZRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 11 02 18 5a 18 6f ?? ?? ?? 0a 13 06 20 [0-4] 7e ?? ?? ?? 04 7b ?? ?? ?? 04 2d 03 26 2b 09}  //weight: 5, accuracy: Low
        $x_5_2 = {11 00 11 02 11 06 1f 10 28 ?? ?? ?? 0a 9c 11 00 11 02 8f ?? ?? ?? 01 25 47 11 01 61 d2 52 11 02 17 58 13 02 11 02 11 00 8e 69 fe 04 2d a8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CloudZRAT_DC_2147968541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CloudZRAT.DC!MTB"
        threat_id = "2147968541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CloudZRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "<Module>{16c0d3f9-d3ce-4316-a1ea-fabcc3854b4f}" ascii //weight: 10
        $x_10_2 = "<Module>{3D240462-E823-4AF4-8325-AEF0BFEB5D19}" ascii //weight: 10
        $x_10_3 = "<Module>{35249F5B-F77E-42F8-BC3D-E5C1C5E9124F}" ascii //weight: 10
        $x_10_4 = "<Module>{ee12803f-11d6-474e-aa66-fff21ee88c6e}" ascii //weight: 10
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

