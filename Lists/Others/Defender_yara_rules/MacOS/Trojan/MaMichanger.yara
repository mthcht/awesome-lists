rule Trojan_MacOS_MaMichanger_2147745559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/MaMichanger!MTB"
        threat_id = "2147745559"
        type = "Trojan"
        platform = "MacOS: "
        family = "MaMichanger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loadMaMiAtPath" ascii //weight: 1
        $x_1_2 = "relaunchWithPrivilegesAndParams" ascii //weight: 1
        $x_1_3 = "mami_activity" ascii //weight: 1
        $x_1_4 = "macup_activity" ascii //weight: 1
        $x_1_5 = "setPrivilagesToFile" ascii //weight: 1
        $x_1_6 = "SlyBootsCore" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

