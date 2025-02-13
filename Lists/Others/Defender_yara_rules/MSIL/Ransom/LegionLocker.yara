rule Ransom_MSIL_LegionLocker_DA_2147780579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LegionLocker.DA!MTB"
        threat_id = "2147780579"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LegionLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LegionLocker2.1" ascii //weight: 1
        $x_1_2 = "@.themida" ascii //weight: 1
        $x_1_3 = "XBundlerTlsHelper" ascii //weight: 1
        $x_1_4 = "skipactivexreg" ascii //weight: 1
        $x_1_5 = "WinLicenseInstance" ascii //weight: 1
        $x_1_6 = "logstatus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

