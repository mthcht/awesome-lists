rule TrojanSpy_AndroidOS_Realrat_D_2147811157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Realrat.D!MTB"
        threat_id = "2147811157"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Realrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 52 65 6d 6f 74 65 [0-32] 2f 72 65 71 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_2 = "/send_sms" ascii //weight: 1
        $x_1_3 = "/hide" ascii //weight: 1
        $x_1_4 = "/send_last_sms" ascii //weight: 1
        $x_1_5 = "_smsgir_messagereceived" ascii //weight: 1
        $x_1_6 = "install.txt" ascii //weight: 1
        $x_1_7 = "msgid.txt" ascii //weight: 1
        $x_1_8 = "Lcom/reza/sh/deviceinfo/DiviceInfo" ascii //weight: 1
        $x_1_9 = "teodor.iromizban.ir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_AndroidOS_Realrat_E_2147815584_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Realrat.E!MTB"
        threat_id = "2147815584"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Realrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.teodor.amir8" ascii //weight: 1
        $x_1_2 = "PNSMS" ascii //weight: 1
        $x_1_3 = "hideAppIcon" ascii //weight: 1
        $x_1_4 = "upload.php?" ascii //weight: 1
        $x_1_5 = "send_last_sms" ascii //weight: 1
        $x_1_6 = "install.txt" ascii //weight: 1
        $x_1_7 = "contactsutils" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Realrat_F_2147816203_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Realrat.F!MTB"
        threat_id = "2147816203"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Realrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "upload&androidid=" ascii //weight: 1
        $x_1_2 = "rat.php" ascii //weight: 1
        $x_1_3 = "hideicon" ascii //weight: 1
        $x_1_4 = "upload.php?" ascii //weight: 1
        $x_1_5 = "uploadsms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Realrat_I_2147828147_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Realrat.I!MTB"
        threat_id = "2147828147"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Realrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hideservice_BR" ascii //weight: 1
        $x_1_2 = "getAllContacts" ascii //weight: 1
        $x_1_3 = "Contacts2Wrapper" ascii //weight: 1
        $x_1_4 = "getAllCalls" ascii //weight: 1
        $x_1_5 = "SmsWrapper" ascii //weight: 1
        $x_1_6 = "fakemain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Realrat_I_2147828147_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Realrat.I!MTB"
        threat_id = "2147828147"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Realrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendmultiparttextmessage" ascii //weight: 1
        $x_1_2 = "did you forget to call activity" ascii //weight: 1
        $x_1_3 = "/receive.php" ascii //weight: 1
        $x_1_4 = "getcontacts" ascii //weight: 1
        $x_1_5 = "hideicon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

