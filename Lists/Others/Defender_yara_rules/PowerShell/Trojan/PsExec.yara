rule Trojan_PowerShell_PsExec_SL_2147973970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PsExec.SL!MTB"
        threat_id = "2147973970"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PsExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe" wide //weight: 10
        $x_10_2 = "-NetQosPolicy" wide //weight: 10
        $x_10_3 = "-AppPathNameMatchCondition" wide //weight: 10
        $x_10_4 = "-ThrottleRateActionBitsPerSecond" wide //weight: 10
        $x_10_5 = "Test_MsSense_Choke" wide //weight: 10
        $x_1_6 = "senseir.exe" wide //weight: 1
        $x_1_7 = "MsSense.exe" wide //weight: 1
        $x_1_8 = "SenseNdr.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_PsExec_SI_2147982030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PsExec.SI!MTB"
        threat_id = "2147982030"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PsExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$(curl -s http://" wide //weight: 1
        $x_1_2 = "-d $(env|base64|" wide //weight: 1
        $x_1_3 = "tr -d '\\n'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

