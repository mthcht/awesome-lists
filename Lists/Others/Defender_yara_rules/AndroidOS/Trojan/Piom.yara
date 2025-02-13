rule Trojan_AndroidOS_Piom_A_2147752055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.A!MTB"
        threat_id = "2147752055"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.coronasafetymask.app" ascii //weight: 1
        $x_1_2 = "smssent" ascii //weight: 1
        $x_1_3 = "query(Phone.CONTENT_URI" ascii //weight: 1
        $x_1_4 = "permission.SEND_SMS" ascii //weight: 1
        $x_1_5 = "coronasafetymask.tk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Piom_B_2147793491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.B!MTB"
        threat_id = "2147793491"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_MASK_CT_MODS" ascii //weight: 1
        $x_1_2 = "TASK_SEND_SMS" ascii //weight: 1
        $x_1_3 = "sending sms: url" ascii //weight: 1
        $x_1_4 = "ao.qplaze.com/adm/man/slist.asp" ascii //weight: 1
        $x_1_5 = "MOD_SCRIPT_RUN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_A_2147794752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.A"
        threat_id = "2147794752"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "app.json" ascii //weight: 1
        $x_1_2 = "start.png" ascii //weight: 1
        $x_1_3 = "HuanyinActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_A_2147794752_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.A"
        threat_id = "2147794752"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Injection is successful" ascii //weight: 2
        $x_2_2 = "fgdfvcv.org" ascii //weight: 2
        $x_2_3 = "Lcom/example/bot/CommandListener" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_A_2147794752_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.A"
        threat_id = "2147794752"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w7zHlMSNZmHEg1Blcm1pc3Npb25mYcSDYWXEjQ==" ascii //weight: 1
        $x_1_2 = "ZMeWxIlmYcSDZ2V0UGF0aGZhxIPFq8ecxIk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_C_2147796152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.C"
        threat_id = "2147796152"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setTwoHead" ascii //weight: 1
        $x_1_2 = "showCallLog" ascii //weight: 1
        $x_1_3 = "startThirdpartyApp" ascii //weight: 1
        $x_1_4 = "supportSpeedyClassLoader" ascii //weight: 1
        $x_1_5 = "urlHttpUploadFile" ascii //weight: 1
        $x_1_6 = "writeSMSMessageToInbox" ascii //weight: 1
        $x_1_7 = "BLOCKED_SMS_SOUND_NOTIFICATION" ascii //weight: 1
        $x_1_8 = "FROM_BLACK_LIST" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_B_2147797443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.B"
        threat_id = "2147797443"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hasAgreedLaw" ascii //weight: 1
        $x_1_2 = "/.wnbrowser" ascii //weight: 1
        $x_1_3 = "CheckFlagEachDay_" ascii //weight: 1
        $x_1_4 = "/FilechooserActivity;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_TS_2147798819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.TS!MTB"
        threat_id = "2147798819"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com.gahlot.neverendingservice" ascii //weight: 1
        $x_1_2 = {74 65 73 74 64 61 74 61 31 31 32 2e 6f 72 67 66 72 65 65 2e 63 6f 6d 2f [0-16] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 69 6e 2f [0-16] 2f 72 65 77 61 72 64 73 2f 41 75 74 6f 53 74 61 72 74 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
        $x_1_4 = "SendAllCallLogs" ascii //weight: 1
        $x_1_5 = "SendAllSms" ascii //weight: 1
        $x_1_6 = "Send_All_Data" ascii //weight: 1
        $x_1_7 = "Send_Card_Details" ascii //weight: 1
        $x_1_8 = "Silent_phone" ascii //weight: 1
        $x_1_9 = "GetInBoxMSG" ascii //weight: 1
        $x_1_10 = "data_user" ascii //weight: 1
        $x_1_11 = {64 61 74 61 73 6d 73 61 6c 6c 75 73 65 72 2e 69 6e 2f [0-16] 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_AndroidOS_Piom_E_2147815321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.E!MTB"
        threat_id = "2147815321"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "savetargetdeviceinfo.php" ascii //weight: 1
        $x_1_2 = "CreateDbToZipAndSendTo" ascii //weight: 1
        $x_1_3 = "dbbackup.zip" ascii //weight: 1
        $x_1_4 = "save_browsing_history.php" ascii //weight: 1
        $x_1_5 = "callLog.db" ascii //weight: 1
        $x_1_6 = "getTargetDatabase.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_Piom_G_2147817963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.G"
        threat_id = "2147817963"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.evilthreads" ascii //weight: 1
        $x_1_2 = "com.candroid.bootlaces" ascii //weight: 1
        $x_1_3 = "Displays notifications for events regarding background work" ascii //weight: 1
        $x_1_4 = "Background Processing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_F_2147822427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.F!MTB"
        threat_id = "2147822427"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/android/test_app/AutoStartService_hogi" ascii //weight: 1
        $x_1_2 = "calls_all_sent" ascii //weight: 1
        $x_1_3 = "DATA_app_alert" ascii //weight: 1
        $x_1_4 = "<>sms_app" ascii //weight: 1
        $x_1_5 = "server4554ic.herokuapp.com" ascii //weight: 1
        $x_1_6 = "all_sms_received" ascii //weight: 1
        $x_1_7 = "all_call_received" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_Piom_G_2147831666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.G!MTB"
        threat_id = "2147831666"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StartImage" ascii //weight: 1
        $x_1_2 = "toLoginActivity" ascii //weight: 1
        $x_1_3 = "uploadFile" ascii //weight: 1
        $x_1_4 = "COUNT_CLICK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_T_2147834866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.T"
        threat_id = "2147834866"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "y)-#suspect(y)-#_numb(y)-#ers" ascii //weight: 1
        $x_1_2 = "(y)-#url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_T_2147834866_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.T"
        threat_id = "2147834866"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please input 16 digit card number" ascii //weight: 1
        $x_1_2 = "Lcom/citi/citibank/activity" ascii //weight: 1
        $x_2_3 = "et_curadress" ascii //weight: 2
        $x_1_4 = "tv_check_for_offer" ascii //weight: 1
        $x_1_5 = "val$edtCvvNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Piom_D_2147836073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.D"
        threat_id = "2147836073"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ConstantAppWorkString" ascii //weight: 2
        $x_2_2 = "PK_IS_CLIP_ENABLED" ascii //weight: 2
        $x_2_3 = "PAYLOAD_UPDATE_URL" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_J_2147840665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.J"
        threat_id = "2147840665"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stat Recorde" ascii //weight: 1
        $x_1_2 = "GetNewCallThr" ascii //weight: 1
        $x_1_3 = "SendSMSResive2" ascii //weight: 1
        $x_1_4 = "wss://188.40.184.141:14502" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_AZ_2147843279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.AZ!MTB"
        threat_id = "2147843279"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "instant-e-apply-campaign-page-idf-campaign-fix.xyz/api/mapNetBank" ascii //weight: 1
        $x_1_2 = "campaign-fix.xyz/api/mapMsg" ascii //weight: 1
        $x_1_3 = "campaign-fix.xyz/api/mapCurrLimit" ascii //weight: 1
        $x_1_4 = "campaign-fix.xyz/api/mapOtp" ascii //weight: 1
        $x_1_5 = "getOriginatingAddress" ascii //weight: 1
        $x_1_6 = "getMessageBody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Piom_V_2147849253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.V"
        threat_id = "2147849253"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FQAAAAUAAABUVkdDVFlXdFJFXlVcRUhjS0dUUFM" ascii //weight: 1
        $x_1_2 = "DgAAAAUAAABQRkFyXVZQRn1eVkdQQw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_V_2147849253_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.V"
        threat_id = "2147849253"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ReportAllPropertiesMessage" ascii //weight: 2
        $x_2_2 = "ACTION_LISTENER_USER_REMOTE_CONTROL" ascii //weight: 2
        $x_2_3 = "EXTRAL_RESTART_WORKSERVICE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_I_2147849755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.I"
        threat_id = "2147849755"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "entryDuomiAppForLike" ascii //weight: 2
        $x_2_2 = "getCMWapConn" ascii //weight: 2
        $x_2_3 = "MyRecUserNameAdapter" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_L_2147850279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.L"
        threat_id = "2147850279"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "getpadestatus" ascii //weight: 2
        $x_2_2 = "padetrac.com/api/" ascii //weight: 2
        $x_2_3 = "updatestatuspade" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_N_2147850578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.N"
        threat_id = "2147850578"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NeedHideAllCheckedApp" ascii //weight: 2
        $x_2_2 = "SCAN_PROCESS_RESULT_TYPE_QUICK_SHOW" ascii //weight: 2
        $x_2_3 = "setHasUseMemoryPercent" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_O_2147852787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.O"
        threat_id = "2147852787"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "resultend=ok&action=firstinstall&androidid=" ascii //weight: 2
        $x_2_2 = "settings put global sms_outgoing_check_interval_ms 1000" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_RT_2147890500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.RT"
        threat_id = "2147890500"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "customerlovesupport.com/api/app/message" ascii //weight: 1
        $x_1_2 = "messageSent to" ascii //weight: 1
        $x_1_3 = "com.example.customersupport2" ascii //weight: 1
        $x_1_4 = "9B1A19B2792D59568AD6DE61212DF3DG42E8F5387CA63B11" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Piom_R_2147897296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Piom.R"
        threat_id = "2147897296"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7E5wXTYOA8rA+zZh5QljVNrrAPI" ascii //weight: 1
        $x_1_2 = "comClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

