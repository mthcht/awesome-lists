rule Trojan_PowerShell_PsExec_SL_2147973960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PsExec.SL!MTB"
        threat_id = "2147973960"
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

