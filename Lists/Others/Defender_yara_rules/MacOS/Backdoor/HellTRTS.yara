rule Backdoor_MacOS_HellTRTS_B_2147748626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/HellTRTS.B!MTB"
        threat_id = "2147748626"
        type = "Backdoor"
        platform = "MacOS: "
        family = "HellTRTS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HellRaiser Configurator" ascii //weight: 2
        $x_1_2 = "by dchkg" ascii //weight: 1
        $x_1_3 = "OpenResourceMovie%o<Movie>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_HellTRTS_C_2147748715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/HellTRTS.C!MTB"
        threat_id = "2147748715"
        type = "Backdoor"
        platform = "MacOS: "
        family = "HellTRTS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HellRaiser has been installed" ascii //weight: 2
        $x_1_2 = "dchkg.perso.wanadoo.fr" ascii //weight: 1
        $x_1_3 = "SMTP Grabber 2.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

