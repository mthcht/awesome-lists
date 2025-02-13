rule HackTool_AndroidOS_Penetho_A_2147782884_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Penetho.A!MTB"
        threat_id = "2147782884"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Penetho"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PenetratePrefs" ascii //weight: 1
        $x_1_2 = "ReverseBroker" ascii //weight: 1
        $x_1_3 = "password_generation" ascii //weight: 1
        $x_1_4 = "OOPS_NOTREVERSIBLE" ascii //weight: 1
        $x_1_5 = "org.underdev.penetratepro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

