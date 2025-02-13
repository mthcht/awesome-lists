rule Trojan_MSIL_Rescoms_BQ_2147795514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rescoms.BQ!MTB"
        threat_id = "2147795514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rescoms"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "OnStressLevelExceeded" ascii //weight: 3
        $x_3_2 = "powershell" ascii //weight: 3
        $x_3_3 = "Test-NetConnection" ascii //weight: 3
        $x_3_4 = "add_StressLimitExceeded" ascii //weight: 3
        $x_3_5 = "5bwBuAAAAMQAuADAALgAwAC4AMAAAADgACAABAEEAcwBzAGUAbQBiAGwAeQAgAFYAZQByAHMA" ascii //weight: 3
        $x_3_6 = "Explorer_Server" ascii //weight: 3
        $x_3_7 = "FromBase64String" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

