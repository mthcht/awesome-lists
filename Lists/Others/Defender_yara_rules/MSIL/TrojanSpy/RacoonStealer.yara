rule TrojanSpy_MSIL_RacoonStealer_2147765662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/RacoonStealer!MTB"
        threat_id = "2147765662"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RacoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Impersonate" wide //weight: 1
        $x_1_2 = "PXcli.{0}" wide //weight: 1
        $x_1_3 = "Virtual environment detected!" wide //weight: 1
        $x_1_4 = "Exiting!" wide //weight: 1
        $x_1_5 = "AgileDotNetRT64" wide //weight: 1
        $x_1_6 = "19f93e2a-4d97-4e0c-ade5-972e41ee6cf8" wide //weight: 1
        $x_1_7 = "c3104e36-971c-4511-9186-d641f3bc572a" wide //weight: 1
        $x_1_8 = "_Initialize64" wide //weight: 1
        $x_1_9 = "_AtExit64" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanSpy_MSIL_RacoonStealer_PA_2147766207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/RacoonStealer.PA!MTB"
        threat_id = "2147766207"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RacoonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "debuggableattribute" ascii //weight: 1
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "injectionpath" ascii //weight: 1
        $x_1_4 = "0e9e1b9d-2e60-4da2-9bef-9084f79207a0" wide //weight: 1
        $x_1_5 = "90b98812-e65d-40b8-ae3e-c16d7e819619" wide //weight: 1
        $x_1_6 = "AgileDotNetRT64" wide //weight: 1
        $x_1_7 = "_Initialize64" wide //weight: 1
        $x_1_8 = "_AtExit64" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

