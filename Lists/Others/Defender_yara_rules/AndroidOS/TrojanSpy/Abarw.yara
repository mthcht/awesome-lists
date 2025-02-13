rule TrojanSpy_AndroidOS_Abarw_A_2147831276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Abarw.A!MTB"
        threat_id = "2147831276"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Abarw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ArabWareSMS" ascii //weight: 1
        $x_1_2 = "_real_time_check" ascii //weight: 1
        $x_1_3 = "SaidHack" ascii //weight: 1
        $x_1_4 = "listMapData" ascii //weight: 1
        $x_1_5 = "sms_child_listener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Abarw_B_2147844326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Abarw.B!MTB"
        threat_id = "2147844326"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Abarw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ArabWareSMS" ascii //weight: 1
        $x_1_2 = "_real_time_check" ascii //weight: 1
        $x_1_3 = "_start_attack" ascii //weight: 1
        $x_1_4 = "/sendMessage?chat_id=" ascii //weight: 1
        $x_1_5 = "listMapData" ascii //weight: 1
        $x_1_6 = "getDisplayMessageBody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Abarw_C_2147932963_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Abarw.C!MTB"
        threat_id = "2147932963"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Abarw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ArabWareSMS" ascii //weight: 1
        $x_1_2 = "timer_attack" ascii //weight: 1
        $x_1_3 = "droid/child/MainActivity" ascii //weight: 1
        $x_1_4 = "_send_Telgra" ascii //weight: 1
        $x_1_5 = "_start_attack" ascii //weight: 1
        $x_1_6 = "_gotelgram_request_listener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

