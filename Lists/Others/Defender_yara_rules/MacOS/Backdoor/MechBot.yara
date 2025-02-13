rule Backdoor_MacOS_MechBot_A1_2147745843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/MechBot.A1!MTB"
        threat_id = "2147745843"
        type = "Backdoor"
        platform = "MacOS: "
        family = "MechBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "./mech.help" ascii //weight: 1
        $x_1_2 = "0!pipe@energymech" ascii //weight: 1
        $x_1_3 = "s!shell@energymech" ascii //weight: 1
        $x_1_4 = "./randfiles/randsignoff.e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

