rule Backdoor_MacOS_Morcut_A_2147793255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Morcut.A!xp"
        threat_id = "2147793255"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Morcut"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "makeBackdoorResident" ascii //weight: 2
        $x_1_2 = "/tmp/43t8803zz%.8d.XXXX" ascii //weight: 1
        $x_1_3 = "addBackdoorToSLIPlist" ascii //weight: 1
        $x_1_4 = "isBackdoorPresentInSLI:" ascii //weight: 1
        $x_1_5 = "startAgents" ascii //weight: 1
        $x_1_6 = "eventsMonitor" ascii //weight: 1
        $x_1_7 = "injectBundle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

