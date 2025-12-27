rule TrojanSpy_AndroidOS_SAgent_A_2147809244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgent.A!MTB"
        threat_id = "2147809244"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "everyone.evl" ascii //weight: 1
        $x_1_2 = "run To Upload Files Receiver" ascii //weight: 1
        $x_1_3 = "RINGING Incoming CallReceived - last status:" ascii //weight: 1
        $x_1_4 = "SchRecordersService" ascii //weight: 1
        $x_1_5 = "ICON_HIDDEN" ascii //weight: 1
        $x_1_6 = "ICON_CHANGED" ascii //weight: 1
        $x_1_7 = "OPEN_AUTO_START" ascii //weight: 1
        $x_1_8 = "SMSService" ascii //weight: 1
        $x_1_9 = "CallLogService" ascii //weight: 1
        $x_1_10 = "UploadFileService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgent_NW_2147811145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgent.NW!MTB"
        threat_id = "2147811145"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SendWinrarExploit" ascii //weight: 1
        $x_1_2 = "getewayport.txt" ascii //weight: 1
        $x_1_3 = "smbomber" ascii //weight: 1
        $x_1_4 = "getlastsms" ascii //weight: 1
        $x_1_5 = "net.LydiaTeam.lockpage" ascii //weight: 1
        $x_1_6 = "hideapp" ascii //weight: 1
        $x_1_7 = "getallmessage" ascii //weight: 1
        $x_1_8 = "getcontact" ascii //weight: 1
        $x_1_9 = {70 65 79 67 69 72 69 2d 31 35 61 2e 6d 6c [0-21] 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgent_C_2147838012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgent.C!MTB"
        threat_id = "2147838012"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "call_record" ascii //weight: 1
        $x_1_2 = "?ac=chkcm1&uid=" ascii //weight: 1
        $x_1_3 = "YouWillNeverKillMe" ascii //weight: 1
        $x_1_4 = "FRzip112.zip" ascii //weight: 1
        $x_1_5 = "android.permission.RECORD_AUDIO" ascii //weight: 1
        $x_1_6 = "android.permission.READ_CALL_LOG" ascii //weight: 1
        $x_1_7 = "ac=REPX&uid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgent_D_2147840513_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgent.D!MTB"
        threat_id = "2147840513"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 6f 6d 2f 62 72 6f 77 73 65 72 2f 77 65 62 [0-4] 2f 53 6d 73 52 65 63 65 69 76 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 61 70 69 2f 73 6d 73 2d 74 65 73 74 2f [0-16] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_3 = "senderphone4" ascii //weight: 1
        $x_1_4 = "devicemodel4" ascii //weight: 1
        $x_1_5 = "sourcez4" ascii //weight: 1
        $x_1_6 = "getDisplayOriginatingAddress" ascii //weight: 1
        $x_1_7 = "extra_sms_message" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgent_GV_2147956022_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgent.GV!AMTB"
        threat_id = "2147956022"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET_PWDED" ascii //weight: 1
        $x_1_2 = "startTracking" ascii //weight: 1
        $x_1_3 = "PickContact" ascii //weight: 1
        $x_1_4 = "service_heartbeat" ascii //weight: 1
        $x_1_5 = "sendTextMessage" ascii //weight: 1
        $x_1_6 = "takepicture" ascii //weight: 1
        $x_1_7 = "WakeUpActivity" ascii //weight: 1
        $x_1_8 = "SEND_SMS" ascii //weight: 1
        $x_1_9 = "activity_screen_lock_pwd" ascii //weight: 1
        $x_1_10 = "ScreenLockPwdActivity" ascii //weight: 1
        $x_1_11 = "captureCall" ascii //weight: 1
        $x_1_12 = "AudioRecorderService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

