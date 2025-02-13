rule HackTool_MacOS_BrutalGift_A_2147746266_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/BrutalGift.A!MTB"
        threat_id = "2147746266"
        type = "HackTool"
        platform = "MacOS: "
        family = "BrutalGift"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Brutal Gift" ascii //weight: 2
        $x_1_2 = "pagesperso-orange.fr/dchkg/index.html" ascii //weight: 1
        $x_1_3 = "attack completed" ascii //weight: 1
        $x_1_4 = "dchkg.perso.wanadoo.fr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

