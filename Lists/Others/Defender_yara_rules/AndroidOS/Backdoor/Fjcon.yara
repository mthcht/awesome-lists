rule Backdoor_AndroidOS_Fjcon_A_2147817932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Fjcon.A!MTB"
        threat_id = "2147817932"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Fjcon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getSendmsg" ascii //weight: 1
        $x_1_2 = "sendSMSByPlatform" ascii //weight: 1
        $x_1_3 = "getSMSContent" ascii //weight: 1
        $x_1_4 = "getPhoneFromURL" ascii //weight: 1
        $x_1_5 = "encodeSms" ascii //weight: 1
        $x_1_6 = "dialPhoneByPlatform" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

