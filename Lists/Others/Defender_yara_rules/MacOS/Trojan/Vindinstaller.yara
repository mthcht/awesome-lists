rule Trojan_MacOS_Vindinstaller_S_2147744919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Vindinstaller.S!MTB"
        threat_id = "2147744919"
        type = "Trojan"
        platform = "MacOS: "
        family = "Vindinstaller"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vidinstaller/vidinstaller project/" ascii //weight: 2
        $x_2_2 = "setcanadagreaukt.info" ascii //weight: 2
        $x_1_3 = "Copyright 1998-2004 Gilles Vollant" ascii //weight: 1
        $x_1_4 = "X3596Z96481" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

