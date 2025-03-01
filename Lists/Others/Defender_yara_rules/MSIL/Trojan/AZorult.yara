rule Trojan_MSIL_AZorult_RDA_2147846521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AZorult.RDA!MTB"
        threat_id = "2147846521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AZorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "f0eab58d-0246-425f-95eb-a58c0d2a9eee" ascii //weight: 2
        $x_1_2 = "InsertPool" ascii //weight: 1
        $x_1_3 = "AwakePool" ascii //weight: 1
        $x_1_4 = "IncludeIndexer" ascii //weight: 1
        $x_1_5 = "ComputePool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

