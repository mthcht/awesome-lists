rule PWS_MSIL_GameThief_PA_2147754965_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/GameThief.PA!MTB"
        threat_id = "2147754965"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GameThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Growtopia" wide //weight: 5
        $x_1_2 = "ProcessStealer" ascii //weight: 1
        $x_1_3 = "Stealer with AAP bypass" wide //weight: 1
        $x_1_4 = "Steal Google Token" wide //weight: 1
        $x_1_5 = "Spammer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_GameThief_PB_2147754966_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/GameThief.PB!MTB"
        threat_id = "2147754966"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GameThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Stealer" wide //weight: 5
        $x_2_2 = "\\Growtopia\\save.dat" wide //weight: 2
        $x_1_3 = "txtFilenamefud" wide //weight: 1
        $x_1_4 = "GetPasswordBytes" ascii //weight: 1
        $x_1_5 = "BuildStealer_Click" ascii //weight: 1
        $x_1_6 = "Hack" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

