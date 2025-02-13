rule Trojan_AndroidOS_Fakecalls_AB_2147794784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.AB"
        threat_id = "2147794784"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CALLLOGUPLOAD_URL" ascii //weight: 2
        $x_2_2 = "BANK_URL" ascii //weight: 2
        $x_2_3 = "ACTION_SEND_DATA" ascii //weight: 2
        $x_2_4 = "?type=comeOnCall" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_B_2147794864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.B"
        threat_id = "2147794864"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ACTION_SEND_DATA" ascii //weight: 2
        $x_2_2 = "GET_LIMIT_PHONE_NUMBER" ascii //weight: 2
        $x_2_3 = "ALL_PERMISSION" ascii //weight: 2
        $x_2_4 = "I'm busy enough" ascii //weight: 2
        $x_2_5 = "CropYuv" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_C_2147795139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.C"
        threat_id = "2147795139"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.wseped.ww30" ascii //weight: 2
        $x_1_2 = "openqjaanqnauth://hello" ascii //weight: 1
        $x_1_3 = "MSG_LOAD_JOB_START" ascii //weight: 1
        $x_1_4 = "setBtnCLick" ascii //weight: 1
        $x_1_5 = "K_FIRST_LUNCH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_D_2147795525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.D"
        threat_id = "2147795525"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "update_huhu" ascii //weight: 1
        $x_1_2 = "uploadSMSFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_D_2147795525_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.D"
        threat_id = "2147795525"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "onServiceConnected, showAccess:" ascii //weight: 2
        $x_2_2 = "Euh3TQpmNDeOWZMsIy97" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_D_2147795525_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.D"
        threat_id = "2147795525"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CallUpdateTime" ascii //weight: 2
        $x_1_2 = "BlackList" ascii //weight: 1
        $x_1_3 = "setReceiveBlock" ascii //weight: 1
        $x_1_4 = "NumberList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_ZH_2147805109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.ZH"
        threat_id = "2147805109"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "onCallRemoved: number=" ascii //weight: 1
        $x_1_2 = "delete CallLog:" ascii //weight: 1
        $x_1_3 = "callsList" ascii //weight: 1
        $x_1_4 = "blackList Update number:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_E_2147832450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.E"
        threat_id = "2147832450"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "forwardingShowPhone:" ascii //weight: 2
        $x_2_2 = "Success to upload callog" ascii //weight: 2
        $x_2_3 = "KEY_IS_FORWARDING_HAND_UP" ascii //weight: 2
        $x_2_4 = "uploadCallLogFile" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_F_2147836079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.F"
        threat_id = "2147836079"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "REQUEST_UPLOAD_INFO_FILE" ascii //weight: 2
        $x_2_2 = "event_recording_from_server" ascii //weight: 2
        $x_2_3 = "SOCKET_EVENT_SEND_CALL_STARTED_MSG_TO_SERVER" ascii //weight: 2
        $x_2_4 = "SCANNING_ALL_APP" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_G_2147841195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.G"
        threat_id = "2147841195"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KEY_SRC_NUMBER" ascii //weight: 1
        $x_1_2 = "CallOut_Number=" ascii //weight: 1
        $x_1_3 = "KEY_SERVER_IP1" ascii //weight: 1
        $x_1_4 = "delay 2sec call end" ascii //weight: 1
        $x_1_5 = "KEY_TELECOMS_NAME1" ascii //weight: 1
        $x_1_6 = "change overlay number:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_M_2147842874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.M"
        threat_id = "2147842874"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Euh3TQpmNDeOWZMsIy97+" ascii //weight: 1
        $x_1_2 = "APK Download Failed doInBackground catch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_M_2147842874_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.M"
        threat_id = "2147842874"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "checkWhoWhoStatus" ascii //weight: 2
        $x_2_2 = "isInstalledWhoWho" ascii //weight: 2
        $x_2_3 = "runWhoWho" ascii //weight: 2
        $x_2_4 = "requestInstallUnknownApp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_B_2147847026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.B!MTB"
        threat_id = "2147847026"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "no_listener_num" ascii //weight: 1
        $x_1_2 = "intercept_all_phone" ascii //weight: 1
        $x_1_3 = "incoming_transfer" ascii //weight: 1
        $x_1_4 = "record_telephone" ascii //weight: 1
        $x_1_5 = "ko/shinhansavings/phone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_I_2147850581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.I"
        threat_id = "2147850581"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "letscall-msg" ascii //weight: 2
        $x_2_2 = "/app/unbind-agent" ascii //weight: 2
        $x_2_3 = "enabled_call_whitelists" ascii //weight: 2
        $x_2_4 = "isDefaultPhoneCallApp" ascii //weight: 2
        $x_2_5 = "/app/apply-add" ascii //weight: 2
        $x_2_6 = "develop_apk/app_sign.apk" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_P_2147851722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.P"
        threat_id = "2147851722"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://xxxx" ascii //weight: 1
        $x_1_2 = "iPxufxldbi" ascii //weight: 1
        $x_1_3 = "nokoenrul" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_Q_2147853376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.Q"
        threat_id = "2147853376"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "last CallOut number=" ascii //weight: 2
        $x_2_2 = "CALL_IN Number =" ascii //weight: 2
        $x_1_3 = "com.wr7202101273.persist.sss" ascii //weight: 1
        $x_1_4 = "kwo8t4F8ybzu+vw" ascii //weight: 1
        $x_1_5 = "deleteContact_exception" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Fakecalls_S_2147910951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.S"
        threat_id = "2147910951"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tsnte$SecureType$SignAlgorithm" ascii //weight: 1
        $x_1_2 = "Tsnte$c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_R_2147915739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.R"
        threat_id = "2147915739"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eWVlYWIrPj51fmZ_P2J4f3lwfzxzcH96P3J-fD55ZHl" ascii //weight: 1
        $x_1_2 = "/api/applink/requestMainCal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_U_2147915741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.U"
        threat_id = "2147915741"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pymFilxE" ascii //weight: 1
        $x_1_2 = "EAygaIzpkm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_2147919245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.MT"
        threat_id = "2147919245"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autoServiceForwar dingNumber" ascii //weight: 1
        $x_1_2 = "autoServiceCa llNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Fakecalls_HT_2147927145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakecalls.HT"
        threat_id = "2147927145"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakecalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "updateRecordLocationSV" ascii //weight: 1
        $x_1_2 = "thoroughfareSV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

