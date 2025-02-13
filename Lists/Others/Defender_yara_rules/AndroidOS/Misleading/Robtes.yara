rule Misleading_AndroidOS_Robtes_A_361111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:AndroidOS/Robtes.A!MTB"
        threat_id = "361111"
        type = "Misleading"
        platform = "AndroidOS: Android operating system"
        family = "Robtes"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/lkpp.html" ascii //weight: 1
        $x_1_2 = "MyInsertService" ascii //weight: 1
        $x_1_3 = "stopSelf" ascii //weight: 1
        $x_1_4 = "MainWebViewClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

