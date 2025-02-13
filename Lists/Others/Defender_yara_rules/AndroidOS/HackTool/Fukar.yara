rule HackTool_AndroidOS_Fukar_A_2147828235_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Fukar.A!MTB"
        threat_id = "2147828235"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Fukar"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "WUZHREYMGBdaSQMHEQUfCRFGCgUGQwweBF8UEAlFHFlHWlg=" ascii //weight: 3
        $x_1_2 = "cyber.azov" ascii //weight: 1
        $x_1_3 = "start_attack" ascii //weight: 1
        $x_1_4 = "Ddos requests" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_AndroidOS_Fukar_C_2147831568_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Fukar.C!MTB"
        threat_id = "2147831568"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Fukar"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/ddos/stopwar" ascii //weight: 1
        $x_1_2 = "com.ddos.CyberAzov" ascii //weight: 1
        $x_1_3 = "d1wp6m56sqw74a.cloudfront.net/~assets/" ascii //weight: 1
        $x_1_4 = "payload" ascii //weight: 1
        $x_1_5 = "javaScriptEnabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

