rule HackTool_MacOS_XHide_A_2147760891_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/XHide.A!MTB"
        threat_id = "2147760891"
        type = "HackTool"
        platform = "MacOS: "
        family = "XHide"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".pid ./egg bot.conf" ascii //weight: 1
        $x_1_2 = "Fake name process" ascii //weight: 1
        $x_1_3 = "XHide - Process Faker, by Schizoprenic Xnuxer Research" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

