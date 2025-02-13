rule Trojan_MSIL_SchdTask_YA_2147733650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SchdTask.YA!MTB"
        threat_id = "2147733650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SchdTask"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "not a valid port format!" wide //weight: 1
        $x_1_2 = "Can not resolve host name:{0}" wide //weight: 1
        $x_1_3 = "ping count is not a correct format!" wide //weight: 1
        $x_1_4 = "{0} - {1} TTL={2} time={3}" wide //weight: 1
        $x_5_5 = "The result is too large,program store to '{0}'.Please download it manully" wide //weight: 5
        $x_5_6 = "WriteTaskRes" wide //weight: 5
        $x_5_7 = "AvailableCount" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SchdTask_YB_2147733651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SchdTask.YB!MTB"
        threat_id = "2147733651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SchdTask"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Powerkatz32" wide //weight: 1
        $x_1_2 = "Powerkatz64" wide //weight: 1
        $x_2_3 = "GetData: not found taskName" wide //weight: 2
        $x_2_4 = "Delete Ex:" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

