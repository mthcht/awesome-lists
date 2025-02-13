rule TrojanSpy_MSIL_Starter_ARA_2147910322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Starter.ARA!MTB"
        threat_id = "2147910322"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://r2.ohyoulookstupid.win/" wide //weight: 2
        $x_2_2 = "-WebSession $S -UseBasicParsing).Content" wide //weight: 2
        $x_2_3 = "Invoke-Expression (Invoke-WebRequest" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

