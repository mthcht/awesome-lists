rule Trojan_AndroidOS_Mamont_R_2147896325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.R"
        threat_id = "2147896325"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {63 68 61 74 5f 69 64 3d 2d 31 30 30 31 39 39 36 32 36 30 34 30 30 26 74 65 78 74 3d d0 92 d0 be d1 80 d0 ba d0 b5 d1 80 3a}  //weight: 2, accuracy: High
        $x_2_2 = "@shootingupsome" ascii //weight: 2
        $x_2_3 = "CodeFromPanel" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Mamont_C_2147899816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.C"
        threat_id = "2147899816"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sendsms/AutoClickService" ascii //weight: 2
        $x_2_2 = "/err.php?i1=" ascii //weight: 2
        $x_2_3 = "/needed.php?i1=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_B_2147899823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.B"
        threat_id = "2147899823"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isTelegramSended_1" ascii //weight: 1
        $x_1_2 = "SmsGrabber: No messages found" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_A_2147901525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.A!MTB"
        threat_id = "2147901525"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/needed.php?i1=" ascii //weight: 1
        $x_1_2 = "/bal.php?i1=" ascii //weight: 1
        $x_1_3 = "/dropnnna.txt" ascii //weight: 1
        $x_1_4 = "com/example/sendsms" ascii //weight: 1
        $x_1_5 = "cf56445.tw1.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Mamont_B_2147910501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.B!MTB"
        threat_id = "2147910501"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zzzz/aaa/core/SmsReceiver" ascii //weight: 1
        $x_1_2 = "com.wefawvevw.app" ascii //weight: 1
        $x_1_3 = "ru.yoo.yoomone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_F_2147914853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.F"
        threat_id = "2147914853"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KORONA_PAY_TRANSFER_COMPLETION" ascii //weight: 2
        $x_2_2 = "handleSimTransferConfirmationCodeReceipt" ascii //weight: 2
        $x_2_3 = "getNeedDefaultSmsAppPermission" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_C_2147915010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.C!MTB"
        threat_id = "2147915010"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SENDING_SMS" ascii //weight: 1
        $x_1_2 = "SmsController" ascii //weight: 1
        $x_1_3 = "sendFromAllSimCards" ascii //weight: 1
        $x_1_4 = "getKORONA_PAY_PAYMENT_COMPLETED" ascii //weight: 1
        $x_1_5 = "TelephonyRat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_M_2147915767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.M"
        threat_id = "2147915767"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.xcc.VmesteFilms.extra.PARAM1" ascii //weight: 2
        $x_2_2 = "VmesteFilms/eceiver" ascii //weight: 2
        $x_2_3 = "com.xcc.VmesteFilms.action.BAZ" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_T_2147918895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.T"
        threat_id = "2147918895"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "onTelephonyRatCommandExecuted" ascii //weight: 2
        $x_2_2 = "sendPhoneNumberToRetransmitter" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_L_2147924225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.L"
        threat_id = "2147924225"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "avtovykup.autos/nopessmision" ascii //weight: 2
        $x_2_2 = "readLast10Messages" ascii //weight: 2
        $x_2_3 = "showPermissionAccesMessage" ascii //weight: 2
        $x_2_4 = "checkServerResponseAndRequestPermissions" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Mamont_G_2147925740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.G"
        threat_id = "2147925740"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PROWEL GET BAL" ascii //weight: 2
        $x_2_2 = "sendsms/TFActivity" ascii //weight: 2
        $x_2_3 = "CARD2SIMSBER" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_E_2147931200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.E!MTB"
        threat_id = "2147931200"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getSmsHistory" ascii //weight: 1
        $x_1_2 = "SmsSubMapping" ascii //weight: 1
        $x_1_3 = "saveReceivedSms" ascii //weight: 1
        $x_1_4 = "ru/cvv/core/SMSBroadcastReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_H_2147935546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.H!MTB"
        threat_id = "2147935546"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/example/application" ascii //weight: 1
        $x_1_2 = "ExecutionTelephonyRatCommand" ascii //weight: 1
        $x_1_3 = "SmsArchiveInterception" ascii //weight: 1
        $x_1_4 = "getDevicePhoneNumbers" ascii //weight: 1
        $x_1_5 = "ArchiveSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_I_2147937875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.I!MTB"
        threat_id = "2147937875"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ru/putisha/app/SmsService" ascii //weight: 1
        $x_1_2 = "get_message_history" ascii //weight: 1
        $x_1_3 = "SmsSubMapping" ascii //weight: 1
        $x_1_4 = "get_calls_history" ascii //weight: 1
        $x_1_5 = {d0 9d d0 9e d0 92 d0 9e d0 95 20 53 4d 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_J_2147940012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.J!MTB"
        threat_id = "2147940012"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsServiceRestartWorker" ascii //weight: 1
        $x_1_2 = "getAll_phone_numbers" ascii //weight: 1
        $x_1_3 = "foundSimCards" ascii //weight: 1
        $x_1_4 = "processPendingSmsLogs" ascii //weight: 1
        $x_1_5 = "setupSmsSentReceiver" ascii //weight: 1
        $x_1_6 = "handleSmsDefaultApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_K_2147940231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.K!MTB"
        threat_id = "2147940231"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendAppsListToTelegram" ascii //weight: 1
        $x_1_2 = "Lcom/example/testrat/SmsReceiver" ascii //weight: 1
        $x_1_3 = "sendNotificationToTelegram" ascii //weight: 1
        $x_1_4 = "sendTelegramMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_N_2147942314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.N!MTB"
        threat_id = "2147942314"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendPostRequestSmsApp" ascii //weight: 1
        $x_1_2 = "sentSpecialSendersToday" ascii //weight: 1
        $x_1_3 = "startCheckingForNewSMS" ascii //weight: 1
        $x_1_4 = "delivery-top.ru/send-sms" ascii //weight: 1
        $x_1_5 = "parseAndSendSpecialSMS" ascii //weight: 1
        $x_1_6 = "wss://delivery-top.ru/socket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_L_2147943306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.L!MTB"
        threat_id = "2147943306"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsServiceRestartWorker" ascii //weight: 1
        $x_1_2 = "processPendingSmsLogs" ascii //weight: 1
        $x_1_3 = "getAll_phone_numbers" ascii //weight: 1
        $x_1_4 = "foundSimCards" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_O_2147947802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.O!MTB"
        threat_id = "2147947802"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "doChangeDefaultSmsLegacy" ascii //weight: 1
        $x_1_2 = "initializeTelegramCredentials" ascii //weight: 1
        $x_1_3 = "onAllDocsSent" ascii //weight: 1
        $x_1_4 = "fetchTelegramCommands" ascii //weight: 1
        $x_1_5 = "handleGetAllSms" ascii //weight: 1
        $x_1_6 = "sendSmsPushMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mamont_P_2147947807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.P!MTB"
        threat_id = "2147947807"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lput1cmd/put1root" ascii //weight: 1
        $x_1_2 = "Lputisnare/put1strike" ascii //weight: 1
        $x_1_3 = "put1xploit" ascii //weight: 1
        $x_1_4 = "Lputiware/put1drive" ascii //weight: 1
        $x_1_5 = "Lputi0per/put1root" ascii //weight: 1
        $x_1_6 = "Lput1drive/put1daemon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Mamont_Q_2147951873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mamont.Q!MTB"
        threat_id = "2147951873"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mamont"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "onlyfans/NZTTransport$sendNewInstall" ascii //weight: 1
        $x_1_2 = "dcimFileList" ascii //weight: 1
        $x_1_3 = "onlyfans.NZTTransport" ascii //weight: 1
        $x_1_4 = "getGalleryCameraImages" ascii //weight: 1
        $x_1_5 = "getOneCameraPhoto" ascii //weight: 1
        $x_1_6 = "onlyfans/NZTTransport$sendHttpPostFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

