rule HackTool_AndroidOS_Faceniff_A_2147784807_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Faceniff.A!MTB"
        threat_id = "2147784807"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Faceniff"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "faceniff.ponury.net" ascii //weight: 1
        $x_1_2 = "Stealth mode is much slower" ascii //weight: 1
        $x_1_3 = "This phone is not rooted" ascii //weight: 1
        $x_1_4 = "Trying to fetch facebook profile photo" ascii //weight: 1
        $x_1_5 = "application locked" ascii //weight: 1
        $x_1_6 = "tb_stealth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

