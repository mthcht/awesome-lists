rule TrojanSpy_AndroidOS_SpyAgent_F_2147798511_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgent.F"
        threat_id = "2147798511"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ServicesDemo3.dll" ascii //weight: 1
        $x_1_2 = "KURBANISMI" ascii //weight: 1
        $x_1_3 = ".PhonecallReceiver, ServicesDemo3" ascii //weight: 1
        $x_1_4 = "Task2.KeyListen, ServicesDemo3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgent_DB_2147807375_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgent.DB"
        threat_id = "2147807375"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wdsyncer_config_dataBase" ascii //weight: 2
        $x_1_2 = "setDefMsg" ascii //weight: 1
        $x_1_3 = "rec-" ascii //weight: 1
        $x_1_4 = "sentFile" ascii //weight: 1
        $x_1_5 = "uploadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgent_G_2147807591_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgent.G"
        threat_id = "2147807591"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/devicee.apk" ascii //weight: 1
        $x_1_2 = "relax_cuddle.php" ascii //weight: 1
        $x_1_3 = "otherapkinst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgent_I_2147808537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgent.I"
        threat_id = "2147808537"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getSimContactInfoList" ascii //weight: 1
        $x_1_2 = "CallRecordUtil" ascii //weight: 1
        $x_1_3 = "gps_address_city" ascii //weight: 1
        $x_1_4 = "getDownloadFileNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgent_HJ_2147810567_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgent.HJ"
        threat_id = "2147810567"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "monitor_phoneNumber.txt" ascii //weight: 1
        $x_1_2 = "Android/data/com.google.progress/CalRec" ascii //weight: 1
        $x_1_3 = "isendOtherCall" ascii //weight: 1
        $x_1_4 = "Lcom/google/progress/WifiCheckTask" ascii //weight: 1
        $x_1_5 = "call_pd in pauseRecord" ascii //weight: 1
        $x_1_6 = "startConnectServiceTask_WithUsbConnected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgent_C_2147810568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgent.C"
        threat_id = "2147810568"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/CallLogService;" ascii //weight: 1
        $x_1_2 = "/CheckRecordersLogService;" ascii //weight: 1
        $x_1_3 = "everyone.evl" ascii //weight: 1
        $x_1_4 = "CURRANT_RECORD_PART" ascii //weight: 1
        $x_1_5 = "/VitalSignsReceiver;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgent_L_2147810587_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgent.L"
        threat_id = "2147810587"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.kamran.hunzanews" ascii //weight: 2
        $x_1_2 = "checkingSessionMangerForUploading" ascii //weight: 1
        $x_1_3 = "fetchIsMessagesAdded" ascii //weight: 1
        $x_1_4 = "fetchIsContactsAdded" ascii //weight: 1
        $x_1_5 = "saveAppsAdded" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SpyAgent_L_2147810587_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgent.L"
        threat_id = "2147810587"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Managers/CallsManager;" ascii //weight: 1
        $x_1_2 = "sendVoice" ascii //weight: 1
        $x_1_3 = "==========back cam:::" ascii //weight: 1
        $x_1_4 = "getAllTelegramFiles" ascii //weight: 1
        $x_1_5 = "getVoiceNotesPaths" ascii //weight: 1
        $x_1_6 = "/Service/NotificationListener;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgent_K_2147818329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgent.K"
        threat_id = "2147818329"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getLocalAlbumList" ascii //weight: 1
        $x_1_2 = "/home/help" ascii //weight: 1
        $x_1_3 = "getDeviceSerialMD5" ascii //weight: 1
        $x_1_4 = "zcatpxGentrifi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgent_H_2147852548_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgent.H"
        threat_id = "2147852548"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api/juryPandemic" ascii //weight: 1
        $x_1_2 = "isProtectedTextEnabled" ascii //weight: 1
        $x_1_3 = "fetchTelegramContactName" ascii //weight: 1
        $x_1_4 = "api/roamingStammer" ascii //weight: 1
        $x_1_5 = "fetchWhatsAppBusinessContactName" ascii //weight: 1
        $x_1_6 = "searchFBMessages" ascii //weight: 1
        $x_1_7 = "findFBTitle" ascii //weight: 1
        $x_1_8 = "viberTitleArray" ascii //weight: 1
        $x_1_9 = "whatsAppBusinessTitle" ascii //weight: 1
        $x_1_10 = "fbTitleArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgent_J_2147895344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgent.J"
        threat_id = "2147895344"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VoCont_actPh_oneUtil" ascii //weight: 1
        $x_1_2 = "VoSen_sorUtil" ascii //weight: 1
        $x_1_3 = "VoBat_teryUtil" ascii //weight: 1
        $x_1_4 = "VoCo_ntactEm_ailUtil" ascii //weight: 1
        $x_1_5 = "VoStor_ageUtil" ascii //weight: 1
        $x_1_6 = "VoCont_actAd_dressUtil" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

