rule Adware_AndroidOS_SAgent_A_347927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/SAgent.A!MTB"
        threat_id = "347927"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/appasan/Video_List/MainActivity" ascii //weight: 1
        $x_1_2 = "goToVisitsaz" ascii //weight: 1
        $x_1_3 = "icanhazip.com" ascii //weight: 1
        $x_1_4 = "setAdListener" ascii //weight: 1
        $x_1_5 = "/mnt/sdcard/Download/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

