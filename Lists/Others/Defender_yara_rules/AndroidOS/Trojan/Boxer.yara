rule Trojan_AndroidOS_Boxer_B_2147745118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boxer.B!MTB"
        threat_id = "2147745118"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boxer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.software.adult" ascii //weight: 2
        $x_2_2 = "KEY_WAS_OPENED" ascii //weight: 2
        $x_1_3 = "USSDExtNetSvc" ascii //weight: 1
        $x_1_4 = "178533176826" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Boxer_B_2147745118_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boxer.B!MTB"
        threat_id = "2147745118"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boxer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KEY_MSG_DATA_TEXT" ascii //weight: 1
        $x_1_2 = "beginSending" ascii //weight: 1
        $x_1_3 = "scheduleSending" ascii //weight: 1
        $x_1_4 = "sendOpening" ascii //weight: 1
        $x_1_5 = "smsData" ascii //weight: 1
        $x_1_6 = "ActivatorService" ascii //weight: 1
        $x_1_7 = "ActService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_Boxer_C_2147822342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boxer.C!MTB"
        threat_id = "2147822342"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boxer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/hazuu/don/MainActivity;" ascii //weight: 1
        $x_1_2 = "CALLBACK_URL" ascii //weight: 1
        $x_1_3 = "sendSMS" ascii //weight: 1
        $x_1_4 = "a14f98c0bdf1606" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Boxer_A_2147824118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boxer.A!MTB"
        threat_id = "2147824118"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boxer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KEY_MESSAGE_DATA_TEXT" ascii //weight: 1
        $x_1_2 = "getPrefixAndNumber" ascii //weight: 1
        $x_1_3 = "cntryTag" ascii //weight: 1
        $x_1_4 = "KEY_SUBID_RECEIVED" ascii //weight: 1
        $x_1_5 = "beginSending" ascii //weight: 1
        $x_1_6 = "getMmiRunningText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Boxer_D_2147844790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Boxer.D!MTB"
        threat_id = "2147844790"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Boxer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "data/smsbox" ascii //weight: 1
        $x_1_2 = "SMSSender" ascii //weight: 1
        $x_1_3 = "androidbox.su/sms_rss" ascii //weight: 1
        $x_1_4 = "data.xml" ascii //weight: 1
        $x_1_5 = "scene_smslist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

