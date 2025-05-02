rule Trojan_AndroidOS_SmForw_A_2147744047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmForw.A!MTB"
        threat_id = "2147744047"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Q049U0hBWUZN" ascii //weight: 1
        $x_1_2 = "qq:1279525738" ascii //weight: 1
        $x_1_3 = "BAH.java" ascii //weight: 1
        $x_1_4 = "9999-01-15 00:50:00" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmForw_G_2147816666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmForw.G!MTB"
        threat_id = "2147816666"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.yfm.send" ascii //weight: 1
        $x_1_2 = "isMobileNO" ascii //weight: 1
        $x_1_3 = "SmSserver" ascii //weight: 1
        $x_1_4 = "fromphone" ascii //weight: 1
        $x_1_5 = "SendSms" ascii //weight: 1
        $x_1_6 = "getOriginatingAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_SmForw_B_2147829220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmForw.B!MTB"
        threat_id = "2147829220"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "targetPhoneNumberInput" ascii //weight: 1
        $x_1_2 = "kill_app_hint_text" ascii //weight: 1
        $x_1_3 = "default_forward_number" ascii //weight: 1
        $x_1_4 = "target_phone_number_key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmForw_G_2147852114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmForw.G"
        threat_id = "2147852114"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "yYlloIEorthopedic899t" ascii //weight: 2
        $x_2_2 = "vPreiNKapathetic803i" ascii //weight: 2
        $x_2_3 = "gZzouHQpneumonia797h" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmForw_AV_2147940547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmForw.AV"
        threat_id = "2147940547"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cancelNotJoinTimerTask" ascii //weight: 2
        $x_2_2 = "APICAL_NOTIFICATION_ACTION" ascii //weight: 2
        $x_2_3 = "startVideoCallRestTimeCountDownTimer" ascii //weight: 2
        $x_2_4 = "ACTION_VOICE_SYSTEM_CTRL_SCREEN" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

