rule Trojan_MSIL_EDRChoker_DA_2147971094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/EDRChoker.DA!MTB"
        threat_id = "2147971094"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EDRChoker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "EDRChoker" ascii //weight: 10
        $x_1_2 = "MSFT_NetQosPolicySettingData" ascii //weight: 1
        $x_1_3 = "ThrottleRateAction" ascii //weight: 1
        $x_1_4 = "AppPathNameMatchCondition" ascii //weight: 1
        $x_1_5 = "IPProtocolMatchCondition" ascii //weight: 1
        $x_1_6 = "\\\\.\\ROOT\\StandardCimv2" ascii //weight: 1
        $x_1_7 = "SELECT * FROM MSFT_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

