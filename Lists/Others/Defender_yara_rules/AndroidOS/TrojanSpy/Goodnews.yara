rule TrojanSpy_AndroidOS_Goodnews_A_2147761013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Goodnews.A!MTB"
        threat_id = "2147761013"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Goodnews"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "please make sure it is in the format of" ascii //weight: 1
        $x_1_2 = "Unable to set test device advertising id" ascii //weight: 1
        $x_1_3 = "To Activate your Tiktok please follow next instruction" ascii //weight: 1
        $x_1_4 = "Watch full Video to get Offer" ascii //weight: 1
        $x_1_5 = "mediation_tiktok_network" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

