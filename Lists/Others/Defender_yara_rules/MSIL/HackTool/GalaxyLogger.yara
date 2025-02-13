rule HackTool_MSIL_GalaxyLogger_2147692592_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/GalaxyLogger"
        threat_id = "2147692592"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GalaxyLogger"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "performSteal" ascii //weight: 1
        $x_1_2 = "clipboardLogging" ascii //weight: 1
        $x_1_3 = "zKeyboardLogStr" ascii //weight: 1
        $x_1_4 = "getSelfDestructDate" ascii //weight: 1
        $x_1_5 = "ForceSteamLogin" ascii //weight: 1
        $x_1_6 = "GalaxyLogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_MSIL_GalaxyLogger_2147692592_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/GalaxyLogger"
        threat_id = "2147692592"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GalaxyLogger"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ForceSteamLogin" ascii //weight: 1
        $x_5_2 = "GalaxyLogger" ascii //weight: 5
        $x_1_3 = "slooTyrtsigeRelbasiD" wide //weight: 1
        $x_1_4 = "rgMksaTelbasiD" wide //weight: 1
        $x_1_5 = "DMCelbasiD" wide //weight: 1
        $x_1_6 = "AULelbanE" wide //weight: 1
        $x_1_7 = "snoitpOredloFoN" wide //weight: 1
        $x_1_8 = "gifnoCelbasiD" wide //weight: 1
        $x_1_9 = "RSelbasiD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

