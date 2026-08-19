rule Trojan_MSIL_StealReactor_MDA_2147976440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealReactor.MDA!MTB"
        threat_id = "2147976440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealReactor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 6f 89 00 00 0a 17 73 ?? 00 00 0a 25 02 16 02 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "FlushFinalBlock" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "base64EncodedData" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

