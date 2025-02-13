rule Backdoor_AndroidOS_Ogel_A_2147783789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Ogel.A!MTB"
        threat_id = "2147783789"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Ogel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IMSI_NAKED" ascii //weight: 1
        $x_1_2 = "PhoneCrashActivity" ascii //weight: 1
        $x_1_3 = "writeapk_forsdcard" ascii //weight: 1
        $x_1_4 = "BEGIN SMS Adapter" ascii //weight: 1
        $x_1_5 = "sendSMS sleep" ascii //weight: 1
        $x_1_6 = "cannot fake" ascii //weight: 1
        $x_1_7 = "EnableSmsreply" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_Ogel_A_2147826660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Ogel.A!xp"
        threat_id = "2147826660"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Ogel"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetDefineBackupHost" ascii //weight: 1
        $x_1_2 = "_isKillMySelf" ascii //weight: 1
        $x_1_3 = "_abortBroadcast" ascii //weight: 1
        $x_1_4 = "_hanldSendMsgPendingIntent" ascii //weight: 1
        $x_1_5 = "reBootMsgScreenReceiver" ascii //weight: 1
        $x_1_6 = "SendSmsRongliang" ascii //weight: 1
        $x_1_7 = "wan.mei.chong.dian.qi" ascii //weight: 1
        $x_1_8 = "HAOwupin" ascii //weight: 1
        $x_1_9 = "trim_tail_equalsign" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

