rule Trojan_MacOS_Reshell_A_2147745865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Reshell.A!MTB"
        threat_id = "2147745865"
        type = "Trojan"
        platform = "MacOS: "
        family = "Reshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HellRaiser Master" ascii //weight: 2
        $x_1_2 = "ReprogClone" ascii //weight: 1
        $x_1_3 = "HellRaiser has been installed" ascii //weight: 1
        $x_1_4 = "DEBUG_LOG_PRIVATE.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

