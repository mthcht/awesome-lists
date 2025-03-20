rule Trojan_AndroidOS_SmsThief_C_2147764482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.C!MTB"
        threat_id = "2147764482"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/test/sms/CallApiService;" ascii //weight: 1
        $x_1_2 = "sicurezzaitalia.duckdns.org" ascii //weight: 1
        $x_1_3 = "/SMS/sms.php" ascii //weight: 1
        $x_1_4 = "msgBody" ascii //weight: 1
        $x_1_5 = "/HeadlessSmsSendService;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_SmsThief_GH_2147780330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.GH!MTB"
        threat_id = "2147780330"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ws://103.85.25.165:7777" ascii //weight: 1
        $x_1_2 = "http://210302.top/" ascii //weight: 1
        $x_1_3 = "keepsms" ascii //weight: 1
        $x_1_4 = "content://sms/inbox" ascii //weight: 1
        $x_1_5 = "lanjie_sms" ascii //weight: 1
        $x_1_6 = "backup trace success" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_SmsThief_S_2147811151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.S!MTB"
        threat_id = "2147811151"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "br.com.helpdev.pnp" ascii //weight: 1
        $x_1_2 = "DataRequest(sender_no=" ascii //weight: 1
        $x_1_3 = "sms_recve" ascii //weight: 1
        $x_1_4 = "getmobilno" ascii //weight: 1
        $x_1_5 = "sms/controller" ascii //weight: 1
        $x_1_6 = "getDisplayMessageBody" ascii //weight: 1
        $x_1_7 = "save_sms.php" ascii //weight: 1
        $x_1_8 = "admin_receiver_status_disabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_AZ_2147814801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.AZ"
        threat_id = "2147814801"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "zebr6/ThisApplication" ascii //weight: 2
        $x_2_2 = "UploadSms.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_AZ_2147814801_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.AZ"
        threat_id = "2147814801"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sms_recve" ascii //weight: 1
        $x_1_2 = "messageaddewss" ascii //weight: 1
        $x_1_3 = {4c 63 6f 6d 2f 68 65 6c 70 64 65 76 [0-20] 73 75 70 70 6f 72 74 2f 72 65 63 65 69 76 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72}  //weight: 1, accuracy: Low
        $x_1_4 = "sendNo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_E_2147831623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.E!MTB"
        threat_id = "2147831623"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/autoo/update" ascii //weight: 1
        $x_1_2 = "VideoH263Activity" ascii //weight: 1
        $x_1_3 = "initializeVideoForSanXingS6" ascii //weight: 1
        $x_1_4 = "com/example/service/HelloService" ascii //weight: 1
        $x_1_5 = "mnt/sdcard/pk4funs" ascii //weight: 1
        $x_1_6 = "/filesManager/uploadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_H_2147837162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.H"
        threat_id = "2147837162"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "index.php/index/sms/savesms" ascii //weight: 2
        $x_2_2 = "com.secommerce.ecommerce" ascii //weight: 2
        $x_2_3 = "lastPostSmsId" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_T_2147838321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.T"
        threat_id = "2147838321"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vpnwarning2" ascii //weight: 1
        $x_1_2 = "shortall_BR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_T_2147838321_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.T"
        threat_id = "2147838321"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "log/BadSMSReceiver;" ascii //weight: 2
        $x_2_2 = "AtFwdService$sendContactsText" ascii //weight: 2
        $x_2_3 = "SendContentByMail" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_U_2147839853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.U"
        threat_id = "2147839853"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/cover.html?dID=" ascii //weight: 2
        $x_2_2 = "GetMobileDomain" ascii //weight: 2
        $x_2_3 = "jsaopdjpasdoas.online/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_V_2147839976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.V"
        threat_id = "2147839976"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&action=sms&network=" ascii //weight: 2
        $x_2_2 = "/up_file.php?response=true&id=" ascii //weight: 2
        $x_2_3 = "&accservice=empity&port=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_W_2147840476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.W"
        threat_id = "2147840476"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "5777990726BRI/installed.php?dev=" ascii //weight: 2
        $x_2_2 = "com.ngscript.smstest" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_X_2147840598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.X"
        threat_id = "2147840598"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KEY_LAST_READ_SMS_ID" ascii //weight: 2
        $x_2_2 = "readContactsSms" ascii //weight: 2
        $x_2_3 = "/index.php/index/sms/savesms" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_E_2147842594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.E"
        threat_id = "2147842594"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/up_file.php?response=true&id=" ascii //weight: 2
        $x_2_2 = "&action=unsended&model=" ascii //weight: 2
        $x_2_3 = "Private-sms-detected :" ascii //weight: 2
        $x_2_4 = "&action=sms&network=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_I_2147842702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.I"
        threat_id = "2147842702"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hp_getsmsblockstate.php" ascii //weight: 2
        $x_2_2 = "sms_blockstate" ascii //weight: 2
        $x_2_3 = "what_tel_com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_J_2147842753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.J"
        threat_id = "2147842753"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "retrygetpermission" ascii //weight: 2
        $x_2_2 = "mytestprojects.xyz" ascii //weight: 2
        $x_2_3 = "testfirebase/SmsProcessService;" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_K_2147843429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.K"
        threat_id = "2147843429"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "data/install5.php" ascii //weight: 2
        $x_2_2 = "EXTRA_SMS_NO5" ascii //weight: 2
        $x_2_3 = "new sms8" ascii //weight: 2
        $x_2_4 = "EXTRA_SMS_MESSAGE5" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_K_2147843429_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.K"
        threat_id = "2147843429"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.dhruv.smsrecevier" ascii //weight: 1
        $x_1_2 = "/onlinekkpay.wixsite.com" ascii //weight: 1
        $x_1_3 = "doctoreappoinment.wixsite.com" ascii //weight: 1
        $x_1_4 = "customeragistraion.wixsite.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_SmsThief_L_2147843611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.L"
        threat_id = "2147843611"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "trtxtra.com/s" ascii //weight: 2
        $x_2_2 = "dolphin_uid.txt" ascii //weight: 2
        $x_2_3 = "TURBd01EQXdNREF3TUg3TGRHTQ/index.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_M_2147843822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.M"
        threat_id = "2147843822"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SNSDBBSJN/ISSASDS" ascii //weight: 2
        $x_2_2 = "/cover.html?dID=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_N_2147844099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.N"
        threat_id = "2147844099"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Max_Sms_Time" ascii //weight: 2
        $x_2_2 = "getXmsUser" ascii //weight: 2
        $x_2_3 = "XmsApi" ascii //weight: 2
        $x_2_4 = "KEY_LAST_SMS_KEY" ascii //weight: 2
        $x_2_5 = "XmsService.isRunning:" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_O_2147844592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.O"
        threat_id = "2147844592"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/gapks.online/kleanhouz_888a" ascii //weight: 2
        $x_2_2 = "?pass=app168&cmd=sms&sid=%1$s&sms=%2$s" ascii //weight: 2
        $x_2_3 = "android_asset/FPX.html" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_AU_2147849132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.AU!MTB"
        threat_id = "2147849132"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsLogger" ascii //weight: 1
        $x_1_2 = "LOG_CELL_ID" ascii //weight: 1
        $x_1_3 = "com.daddyseye.backupme.call" ascii //weight: 1
        $x_1_4 = "de/android/keeper" ascii //weight: 1
        $x_1_5 = "VoiceLogger" ascii //weight: 1
        $x_1_6 = "MmsObserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_Z_2147849506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.Z"
        threat_id = "2147849506"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&action=sms&network=" ascii //weight: 2
        $x_2_2 = "&cvv2=1&month=2&year=3&model=" ascii //weight: 2
        $x_2_3 = "&lydia=login" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_Z_2147849506_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.Z"
        threat_id = "2147849506"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoginActivity - Configuring screen on/off.." ascii //weight: 1
        $x_1_2 = "Saved remote session info" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_YA_2147850575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.YA"
        threat_id = "2147850575"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "loadUrlWithSystemLanguage" ascii //weight: 2
        $x_2_2 = "getDomain.php?srvc=" ascii //weight: 2
        $x_2_3 = "smsreciver.g4ctsneogzmf7ndrxzld8gfewebq20ef2e.org" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_Q_2147897627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.Q"
        threat_id = "2147897627"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Account And Mobile Number Verify Sucessfully.." ascii //weight: 1
        $x_1_2 = "SMS body forwarded to" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_Q_2147897627_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.Q"
        threat_id = "2147897627"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "robotsmssent.php?iam=" ascii //weight: 2
        $x_2_2 = "Hilt_RobotSMSApp" ascii //weight: 2
        $x_2_3 = "DaggerRobotSMSApp_HiltComponents_SingletonC" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_R_2147899121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.R"
        threat_id = "2147899121"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&text=*New SMS Received* %0A%0A*Sender" ascii //weight: 2
        $x_2_2 = "%0A%0A*Type Perangkat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_S_2147899815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.S"
        threat_id = "2147899815"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "is_fwd_sms" ascii //weight: 2
        $x_2_2 = "ForegroundServiceChannel-CallGirls" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_O_2147902387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.O!MTB"
        threat_id = "2147902387"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.example.bl5s" ascii //weight: 5
        $x_1_2 = "CURRENTNUMBER" ascii //weight: 1
        $x_1_3 = "/bl5/mob.php" ascii //weight: 1
        $x_1_4 = "transferOtp" ascii //weight: 1
        $x_1_5 = "getMessageBody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SmsThief_P_2147902388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.P!MTB"
        threat_id = "2147902388"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 63 6f 6d 2f 64 68 72 75 76 2f 73 6d 73 72 65 63 65 76 69 65 72 ?? ?? 4d 61 69 6e 41 63 74 69 76 69 74 79}  //weight: 5, accuracy: Low
        $x_1_2 = "askagain" ascii //weight: 1
        $x_1_3 = "getDisplayMessageBody" ascii //weight: 1
        $x_1_4 = "sendTextMessage" ascii //weight: 1
        $x_5_5 = "Lcom/bing/chatting/MainActivity" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SmsThief_Q_2147904631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.Q!MTB"
        threat_id = "2147904631"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/app/homecleaning/MainActivity" ascii //weight: 1
        $x_1_2 = "api_spa24125/api_espanol" ascii //weight: 1
        $x_1_3 = "/api.php?sid=%1$s&sms=%2$s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_R_2147904635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.R!MTB"
        threat_id = "2147904635"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.example.onicapp" ascii //weight: 5
        $x_5_2 = "com.example.newlmra" ascii //weight: 5
        $x_1_3 = "MySmsService" ascii //weight: 1
        $x_1_4 = "getMessageBody" ascii //weight: 1
        $x_1_5 = "updateNotification" ascii //weight: 1
        $x_1_6 = "smsModel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SmsThief_AY_2147909152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.AY"
        threat_id = "2147909152"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "smsrecevier/startupOnBootUpReceiver" ascii //weight: 2
        $x_2_2 = "appointmentservice0.wixsite.com" ascii //weight: 2
        $x_2_3 = "complainf13/My_File.txt" ascii //weight: 2
        $x_2_4 = "co.in/admindata.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_SmsThief_K_2147910820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.K!MTB"
        threat_id = "2147910820"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Lcom/omer/smsapp4" ascii //weight: 5
        $x_5_2 = "com.redeem.Redeem_points" ascii //weight: 5
        $x_1_3 = "insertMsgdata" ascii //weight: 1
        $x_1_4 = "verufy_otp_model" ascii //weight: 1
        $x_1_5 = "submit_sms.php" ascii //weight: 1
        $x_1_6 = "SmsBroadcasrReceiver" ascii //weight: 1
        $x_1_7 = "senddatatodb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SmsThief_AS_2147911361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.AS"
        threat_id = "2147911361"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "navigateToMainActivityIfPermissionsGranted" ascii //weight: 2
        $x_2_2 = "auth/admin_info/number" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_AX_2147911362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.AX"
        threat_id = "2147911362"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "jimmyserv.online/web-admin/" ascii //weight: 2
        $x_2_2 = "api/combo/profile" ascii //weight: 2
        $x_2_3 = "ProfileCaseApi" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_CV_2147912362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.CV"
        threat_id = "2147912362"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "check_perm.php?mobile" ascii //weight: 2
        $x_2_2 = "agoogleplayservicesrinrole/R8e6c8e3i5v0e2S5m3s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_FK_2147917651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.FK"
        threat_id = "2147917651"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mnnn.live/api.php" ascii //weight: 2
        $x_2_2 = "nooraz/ThirdActivity" ascii //weight: 2
        $x_2_3 = "nbp-web.myapp.ru.com" ascii //weight: 2
        $x_2_4 = "bopdigital/MyReceiver" ascii //weight: 2
        $x_2_5 = "Your request is successfully submitted.We try to optimize your account.It may take a few hours or days" ascii //weight: 2
        $x_2_6 = "instabrowser/sendSmsToServer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_SmsThief_VA_2147917653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.VA"
        threat_id = "2147917653"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "pay/recive.php?phone=" ascii //weight: 2
        $x_2_2 = "116.202.255.100/add" ascii //weight: 2
        $x_2_3 = "ir/siqe/holo/connect" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_AQ_2147918896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.AQ"
        threat_id = "2147918896"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "in/balaji/MyBroadcastReceiver" ascii //weight: 2
        $x_2_2 = "balaji/MyForegroundService" ascii //weight: 2
        $x_2_3 = "ganeshacarrentals.com/old-messages.php/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_SmsThief_PS_2147927264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.PS"
        threat_id = "2147927264"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "const_off_details" ascii //weight: 2
        $x_2_2 = "const_gcm_send_sms" ascii //weight: 2
        $x_2_3 = "const_on_save_sms" ascii //weight: 2
        $x_2_4 = "const_error_register_bot" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_SmsThief_AP_2147927265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.AP"
        threat_id = "2147927265"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "webservices/register_user_online_banking.php?" ascii //weight: 2
        $x_2_2 = "webservices/add_sms.php?" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_IY_2147928917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.IY"
        threat_id = "2147928917"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "storeSmsInFirebase" ascii //weight: 2
        $x_2_2 = "CREATE TABLE IF NOT EXISTS phone (phone TEXT)" ascii //weight: 2
        $x_2_3 = "icici/DBHandler" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_SmsThief_PA_2147936551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.PA"
        threat_id = "2147936551"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sms/hack/DebugActivity" ascii //weight: 2
        $x_2_2 = "_iamAntik" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsThief_AI_2147936556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsThief.AI"
        threat_id = "2147936556"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "nsameiacwesi" ascii //weight: 2
        $x_2_2 = "phrlscestpafe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

