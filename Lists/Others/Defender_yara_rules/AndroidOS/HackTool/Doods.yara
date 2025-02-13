rule HackTool_AndroidOS_Doods_A_2147843203_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Doods.A!MTB"
        threat_id = "2147843203"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Doods"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "genius/mohammad/loic" ascii //weight: 1
        $x_1_2 = "/loic/ServiceDenier" ascii //weight: 1
        $x_1_3 = "DDOS" ascii //weight: 1
        $x_1_4 = "selectedTargetTV" ascii //weight: 1
        $x_1_5 = "speedTrackbar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

