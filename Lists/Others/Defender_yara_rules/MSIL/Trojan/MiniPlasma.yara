rule Trojan_MSIL_MiniPlasma_Z_2147969364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MiniPlasma.Z!MTB"
        threat_id = "2147969364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MiniPlasma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Software\\Policies\\Microsoft" ascii //weight: 1
        $x_1_2 = "\\CloudFiles" ascii //weight: 1
        $x_1_3 = "\\BlockedApps" ascii //weight: 1
        $x_1_4 = "cldapi.dll" ascii //weight: 1
        $x_1_5 = "Failed to run stage" ascii //weight: 1
        $x_1_6 = "Cleaning up link" ascii //weight: 1
        $x_1_7 = "SetImpersonationToken" ascii //weight: 1
        $x_1_8 = "CfAbortOperation" ascii //weight: 1
        $x_1_9 = "Opened for WriteOwner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MiniPlasma_DA_2147969367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MiniPlasma.DA!MTB"
        threat_id = "2147969367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MiniPlasma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "107"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Software\\Policies\\Microsoft" ascii //weight: 1
        $x_1_2 = "\\CloudFiles" ascii //weight: 1
        $x_1_3 = "\\BlockedApps" ascii //weight: 1
        $x_100_4 = "\\DEMODEMO" ascii //weight: 100
        $x_1_5 = "cldapi.dll" ascii //weight: 1
        $x_1_6 = "CfAbortOperation" ascii //weight: 1
        $x_1_7 = "Opened for WriteOwner" ascii //weight: 1
        $x_1_8 = "Cleaning up link" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

