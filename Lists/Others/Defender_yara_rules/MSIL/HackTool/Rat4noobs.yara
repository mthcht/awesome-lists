rule HackTool_MSIL_Rat4noobs_2147695314_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Rat4noobs"
        threat_id = "2147695314"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rat4noobs"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Rat4Noobs" ascii //weight: 10
        $x_1_2 = "_MsgIn" ascii //weight: 1
        $x_1_3 = "_KillProc" ascii //weight: 1
        $x_1_4 = "_VisitLink" ascii //weight: 1
        $x_1_5 = "_Persistance" ascii //weight: 1
        $x_1_6 = "_RegistryBotKiller" ascii //weight: 1
        $x_1_7 = "TCP Stresser Enabled" wide //weight: 1
        $x_1_8 = "Slowloris" ascii //weight: 1
        $x_1_9 = "Remote Webcam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

