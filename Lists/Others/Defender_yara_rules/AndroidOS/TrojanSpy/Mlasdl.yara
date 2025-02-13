rule TrojanSpy_AndroidOS_Mlasdl_A_2147828944_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Mlasdl.A!MTB"
        threat_id = "2147828944"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Mlasdl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mainActivityHideOrNot" ascii //weight: 1
        $x_1_2 = "recordAmrStart" ascii //weight: 1
        $x_1_3 = "countSmsByStartId" ascii //weight: 1
        $x_1_4 = "getQQVoicesFileInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

