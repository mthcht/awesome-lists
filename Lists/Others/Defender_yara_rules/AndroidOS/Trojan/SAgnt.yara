rule Trojan_AndroidOS_SAgnt_B_2147815409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.B!MTB"
        threat_id = "2147815409"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mmsc.monternet.com" ascii //weight: 1
        $x_1_2 = "SmsObserver" ascii //weight: 1
        $x_1_3 = "sendToServerSms" ascii //weight: 1
        $x_1_4 = "getPone" ascii //weight: 1
        $x_1_5 = "getSmscByImsi" ascii //weight: 1
        $x_1_6 = "SmsPayModel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_C_2147820254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.C!MTB"
        threat_id = "2147820254"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/isjk/ieikd" ascii //weight: 1
        $x_1_2 = "checkRootPermission" ascii //weight: 1
        $x_1_3 = "CODE_BEGAIN_INSTELL" ascii //weight: 1
        $x_1_4 = "sutongji.php" ascii //weight: 1
        $x_1_5 = "getTopActivityPackageName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_E_2147828435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.E!MTB"
        threat_id = "2147828435"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fdd/android/interceptmms" ascii //weight: 1
        $x_1_2 = "getcontentresolver" ascii //weight: 1
        $x_1_3 = "sms_received" ascii //weight: 1
        $x_1_4 = "/content/componentname" ascii //weight: 1
        $x_1_5 = "onstartcommand" ascii //weight: 1
        $x_1_6 = "RetrieveConf:Phone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_I_2147829162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.I!MTB"
        threat_id = "2147829162"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blue/sky/vn/MainActivity" ascii //weight: 1
        $x_1_2 = "type_get_link" ascii //weight: 1
        $x_1_3 = "KENReceiver" ascii //weight: 1
        $x_1_4 = "OpenLinkNotify" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_D_2147829438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.D!MTB"
        threat_id = "2147829438"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/andreszs/smsreceive" ascii //weight: 1
        $x_1_2 = ".bestkedai29.com/api/usersms/" ascii //weight: 1
        $x_1_3 = "defaultSMSDialogCallback" ascii //weight: 1
        $x_1_4 = "sendSMSPayload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_K_2147829505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.K!MTB"
        threat_id = "2147829505"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 00 17 4c 67 ?? ?? ?? ?? ?? ?? 2f ?? ?? 41 70 70 6c 69 63 61 74 69 6f 6e 3b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3b 00 18 4c 67 ?? ?? ?? ?? ?? ?? 2f ?? ?? ?? 41 70 70 6c 69 63 61 74 69 6f 6e 3b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {0b 66 69 6e 64 4c 69 62 72 61 72 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f 65 6c 61 70 73 65 64 52 65 61 6c 74 69 6d 65 00}  //weight: 1, accuracy: High
        $x_2_5 = {04 00 01 00 02 00 00 00 00 00 00 00 19 00 00 00 71 00 ?? 00 00 00 0c 00 6e 10 05 00 03 00 0c 01 1f 01 0b 00 1a 02 ?? 00 6e 20 0d 00 21 00 0c 01 6e 20 ?? 00 10 00 1a 00 ?? 00 70 20 ?? 00 03 00 0e 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SAgnt_G_2147829665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.G!MTB"
        threat_id = "2147829665"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DataHub/deviceJ/sts" ascii //weight: 1
        $x_1_2 = "x_up_client_channel_id" ascii //weight: 1
        $x_1_3 = "clt30/test.jsp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_J_2147830157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.J!MTB"
        threat_id = "2147830157"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/fde/gsActivity" ascii //weight: 1
        $x_1_2 = "dfCancelNoticeService" ascii //weight: 1
        $x_1_3 = "com/as/dfCancelNoticeService" ascii //weight: 1
        $x_1_4 = "sgMainService" ascii //weight: 1
        $x_1_5 = "ytMyReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_Q_2147831105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.Q!MTB"
        threat_id = "2147831105"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "browserurlcollector" ascii //weight: 1
        $x_1_2 = "com.gemius.netpanel" ascii //weight: 1
        $x_1_3 = "HitDetectorReceiver" ascii //weight: 1
        $x_1_4 = "mobilemeter/ui/screen/MainActivity" ascii //weight: 1
        $x_1_5 = "OSCollectorTask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_F_2147831248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.F!MTB"
        threat_id = "2147831248"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/simplemobiletools/teploapp" ascii //weight: 1
        $x_1_2 = "content://sms/sent" ascii //weight: 1
        $x_1_3 = "raremediumwelldone.com/click.php" ascii //weight: 1
        $x_1_4 = "correl.space/ut.php" ascii //weight: 1
        $x_1_5 = "setMobileDataEnabled" ascii //weight: 1
        $x_1_6 = "getPhoneNumber" ascii //weight: 1
        $x_1_7 = "/system/app/Superuser.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_AndroidOS_SAgnt_L_2147831480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.L!MTB"
        threat_id = "2147831480"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sys_send_contents" ascii //weight: 1
        $x_1_2 = "app.lastCalledNumber" ascii //weight: 1
        $x_1_3 = "NotifReceiver" ascii //weight: 1
        $x_1_4 = "SetTnkTracker" ascii //weight: 1
        $x_1_5 = "sendInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_H_2147831664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.H!MTB"
        threat_id = "2147831664"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wap.app.shuihulu.com/Game/GameBank" ascii //weight: 1
        $x_1_2 = "go.sclt10010.com/count.php?" ascii //weight: 1
        $x_1_3 = "getSimOperatorName" ascii //weight: 1
        $x_1_4 = "deleteFile" ascii //weight: 1
        $x_1_5 = "sms_received" ascii //weight: 1
        $x_1_6 = "downloadPlug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_SAgnt_P_2147831665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.P!MTB"
        threat_id = "2147831665"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "enableActivityAutoTracking" ascii //weight: 1
        $x_1_2 = "ru.ok.android.acts.MainActivity" ascii //weight: 1
        $x_1_3 = "/apks/get-link?click_id" ascii //weight: 1
        $x_1_4 = "withPayload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_O_2147832039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.O!MTB"
        threat_id = "2147832039"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "send_sms_timeout" ascii //weight: 1
        $x_1_2 = "PhoneStarService" ascii //weight: 1
        $x_1_3 = "smsrdo" ascii //weight: 1
        $x_1_4 = "CallPhoneUtil" ascii //weight: 1
        $x_1_5 = "deletSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_R_2147832326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.R!MTB"
        threat_id = "2147832326"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/pesocredit/ph" ascii //weight: 1
        $x_1_2 = "ServiceDetector" ascii //weight: 1
        $x_1_3 = "SmsObserver" ascii //weight: 1
        $x_1_4 = "HdbtiService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_S_2147832696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.S!MTB"
        threat_id = "2147832696"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BotAppActivity" ascii //weight: 1
        $x_1_2 = "sendSMS" ascii //weight: 1
        $x_1_3 = "com/app/bot" ascii //weight: 1
        $x_1_4 = "SmsReceiver" ascii //weight: 1
        $x_1_5 = "bot/ServiceController" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_SAgnt_T_2147833248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.T!MTB"
        threat_id = "2147833248"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.willusnin.propugner" ascii //weight: 1
        $x_1_2 = "SpewsYelp" ascii //weight: 1
        $x_1_3 = "BinesRotl" ascii //weight: 1
        $x_1_4 = "startTracking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_W_2147833987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.W!MTB"
        threat_id = "2147833987"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "moua_red.php?" ascii //weight: 1
        $x_1_2 = "HurrayWirelessOA" ascii //weight: 1
        $x_1_3 = "com/snda/youni/YouNi" ascii //weight: 1
        $x_1_4 = "content://sms/inbox" ascii //weight: 1
        $x_1_5 = "uploadContact" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_U_2147834083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.U!MTB"
        threat_id = "2147834083"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dadm/scaffold/ScaffoldActivity" ascii //weight: 1
        $x_1_2 = "/InstallerRestarterService" ascii //weight: 1
        $x_1_3 = "/WorkerAccessibilityService" ascii //weight: 1
        $x_1_4 = "/VNCActivity" ascii //weight: 1
        $x_1_5 = "getRootInActiveWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_V_2147834578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.V!MTB"
        threat_id = "2147834578"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 03 07 02 d5 33 ff 00 da 04 02 02 62 05 49 0b e2 06 03 04 49 06 05 06 50 06 01 04 d8 04 04 01 dd 03 03 0f 49 03 05 03 50 03 01 04 d8 02 02 01 28 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_X_2147836883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.X!MTB"
        threat_id = "2147836883"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 01 6e 10 ?? ?? 09 00 0c 03 21 34 21 a5 23 56 ?? ?? 01 12 01 10}  //weight: 1, accuracy: Low
        $x_1_2 = {48 07 0a 02 48 08 03 00 b7 87 8d 77 4f 07 06 02 d8 00 00 01 d8 07 04 ff 37 70 03 00 01 10 d8 02 02 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_X_2147836883_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.X!MTB"
        threat_id = "2147836883"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {71 00 17 00 00 00 0c 06 07 64 07 46 1a 07 ?? ?? 12 08 1f 08 24 00 07 39 12 0a 1f 0a 04 00 12 0b 1f 0b 04 00 74 06 18 00 06 00 0e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {71 00 29 00 00 00 0c 04 1a 05 62 00 6e 20 28 00 54 00 0c 04 07 41 22 04 19 00 07 49 07 94 07 95 22 06 1c 00 07 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_Y_2147836884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.Y!MTB"
        threat_id = "2147836884"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "datastatisapi.zhuifengzhe.top" ascii //weight: 1
        $x_1_2 = "/logreport" ascii //weight: 1
        $x_1_3 = "/v1/mr?id=" ascii //weight: 1
        $x_1_4 = "android.app.AppGlobals" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_Z_2147836885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.Z!MTB"
        threat_id = "2147836885"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0c 02 21 21 35 10 0c 00 48 01 02 00 df 01 01 3f 8d 11 4f 01 02 00 d8 00 00 01}  //weight: 3, accuracy: High
        $x_1_2 = "com/attd/da" ascii //weight: 1
        $x_1_3 = "/KeeaService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SAgnt_AA_2147836886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AA!MTB"
        threat_id = "2147836886"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/houla/quicken" ascii //weight: 1
        $x_1_2 = "me/thecloud571" ascii //weight: 1
        $x_1_3 = "/ConService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AB_2147836887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AB!MTB"
        threat_id = "2147836887"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 40 6e 10 ?? ?? 04 00 0c 01 1f 01 ?? ?? 12 02 35 02 0b 00 48 03 04 02 b7 23 8d 33 4f 03 01 02 d8 02 02 02}  //weight: 1, accuracy: Low
        $x_1_2 = {21 71 3c 01 03 00 11 00 13 02 10 00 23 23 ?? ?? b1 21 12 04 12 05 35 25 09 00 48 06 07 05 4f 06 03 05 d8 05 05 01 28 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AC_2147837898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AC!MTB"
        threat_id = "2147837898"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tikitaka/sub/MainActivity" ascii //weight: 1
        $x_1_2 = "sensms" ascii //weight: 1
        $x_1_3 = "sendTextMessage" ascii //weight: 1
        $x_1_4 = "/api/keywords-info" ascii //weight: 1
        $x_1_5 = "telpoo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AD_2147838397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AD!MTB"
        threat_id = "2147838397"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSFunction" ascii //weight: 1
        $x_1_2 = "SavePhoneText" ascii //weight: 1
        $x_1_3 = "CheckSendList" ascii //weight: 1
        $x_1_4 = "readRecords" ascii //weight: 1
        $x_1_5 = "OpenWEB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AF_2147838567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AF!MTB"
        threat_id = "2147838567"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "transformSMS" ascii //weight: 1
        $x_1_2 = "getDeviceDetails" ascii //weight: 1
        $x_1_3 = "SmsReceiverHelper" ascii //weight: 1
        $x_1_4 = "rooming_network" ascii //weight: 1
        $x_1_5 = "requestFirstSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AE_2147838904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AE!MTB"
        threat_id = "2147838904"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DevAdminDisabler" ascii //weight: 1
        $x_1_2 = "exts/denmark" ascii //weight: 1
        $x_1_3 = "readMessagesFromDeviceDB" ascii //weight: 1
        $x_1_4 = "getAppList" ascii //weight: 1
        $x_1_5 = "REPORT_INCOMING_MESSAGE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AH_2147839054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AH!MTB"
        threat_id = "2147839054"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Hanyuies" ascii //weight: 1
        $x_1_2 = "decrypt" ascii //weight: 1
        $x_1_3 = "/Bernt" ascii //weight: 1
        $x_1_4 = "loadedApkClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AG_2147839290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AG!MTB"
        threat_id = "2147839290"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sieuhay.vn/show-download" ascii //weight: 1
        $x_1_2 = "sendSMS" ascii //weight: 1
        $x_1_3 = "loadDataFromUrl2" ascii //weight: 1
        $x_1_4 = "com/hamedia/gamestore" ascii //weight: 1
        $x_1_5 = "GrabURL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AI_2147839486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AI!MTB"
        threat_id = "2147839486"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wifiVoid" ascii //weight: 1
        $x_1_2 = "ArabWare" ascii //weight: 1
        $x_1_3 = "_SmS" ascii //weight: 1
        $x_1_4 = "wipeData" ascii //weight: 1
        $x_1_5 = "hideKeyboard" ascii //weight: 1
        $x_1_6 = "com/said/com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AJ_2147840216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AJ!MTB"
        threat_id = "2147840216"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.happyphone.tk/invite.htm" ascii //weight: 1
        $x_1_2 = "rosephp.us29.iisok.net" ascii //weight: 1
        $x_1_3 = "sp_type_bl_server" ascii //weight: 1
        $x_1_4 = "sp_type_last_all_call_log_time" ascii //weight: 1
        $x_1_5 = "sp_type_last_all_sms_time" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_BZ_2147840872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.BZ!MTB"
        threat_id = "2147840872"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6e 10 1a 01 0a 00 0a 03 dc 08 03 02 12 19 33 98 33 00 d8 03 03 01 db 08 03 02 23 87 ba 00 22 08 62 00 70 10 28 01 08 00 1a 09 09 00 6e 20 2d 01 98 00 0c 08 6e 20 2d 01 a8 00 0c 08 6e 10 2e 01 08 00 0c 0a 12 05 12 04 35 34 1b 00 d8 08 04 02 6e 30 20 01 4a 08 0c 08 13 09 10 00 71 20 f7 00 98 00 0a 08 8d 88 4f 08 07 05 d8 05 05 01 d8 04 04 02 28 eb db 08 03 02}  //weight: 2, accuracy: High
        $x_2_2 = {db 08 03 02 23 87 ba 00 28 e4 12 01 22 06 8b 00 6e 10 17 01 0b 00 0c 08 1a 09 97 00 70 30 93 01 86 09 1a 08 97 00 71 10 91 01 08 00 0c 00 12 28 6e 30 92 01 80 06 6e 20 90 01 70 00 0c 01 22 08 60 00 70 20 0f 01 18 00 11 08 0d 02 6e 10 f2 00 02 00 28 f6}  //weight: 2, accuracy: High
        $x_1_3 = "getInstalledApplications" ascii //weight: 1
        $x_1_4 = "getexternalstoragedirectory" ascii //weight: 1
        $x_1_5 = "DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SAgnt_AL_2147841001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AL!MTB"
        threat_id = "2147841001"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deliverPI1" ascii //weight: 1
        $x_1_2 = "sentBR1" ascii //weight: 1
        $x_1_3 = "messengnumm22" ascii //weight: 1
        $x_1_4 = "AutoStart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AM_2147841044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AM!MTB"
        threat_id = "2147841044"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSG_SNED_TO_CONTACTS" ascii //weight: 1
        $x_1_2 = "getSIMContactNumbers" ascii //weight: 1
        $x_1_3 = {53 4d 53 48 61 6e 64 6c 65 72 [0-16] 61 73 68 78 3f 74 3d 73 26 70 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "WebServiceCalling" ascii //weight: 1
        $x_1_5 = "SendToContacts" ascii //weight: 1
        $x_1_6 = "com/example/google/service" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AN_2147841385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AN!MTB"
        threat_id = "2147841385"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsResultListener" ascii //weight: 1
        $x_1_2 = "sms_data.txt" ascii //weight: 1
        $x_1_3 = "ru/playfon/android2sms/service" ascii //weight: 1
        $x_1_4 = "processSmsBroadcast" ascii //weight: 1
        $x_1_5 = "loadTextFromAssets" ascii //weight: 1
        $x_1_6 = "sms_success" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AO_2147841386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AO!MTB"
        threat_id = "2147841386"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsTransaction" ascii //weight: 1
        $x_1_2 = "getContactCount" ascii //weight: 1
        $x_1_3 = "settexttracking" ascii //weight: 1
        $x_1_4 = "setDeliveryReceiverSMS" ascii //weight: 1
        $x_1_5 = "getWifiTrigger" ascii //weight: 1
        $x_1_6 = "testmsg2.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AK_2147843520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AK!MTB"
        threat_id = "2147843520"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mobileInfo" ascii //weight: 1
        $x_1_2 = "getBk_type" ascii //weight: 1
        $x_1_3 = "ip.txt" ascii //weight: 1
        $x_1_4 = "InfoGetter" ascii //weight: 1
        $x_1_5 = "InfoReturner" ascii //weight: 1
        $x_10_6 = "Lcom/example/maomao/BankSplashActivity" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SAgnt_AP_2147846453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AP!MTB"
        threat_id = "2147846453"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "et_card_number" ascii //weight: 1
        $x_1_2 = "/uuid_custom.txt" ascii //weight: 1
        $x_1_3 = "hcv4ur.devs.teatr" ascii //weight: 1
        $x_1_4 = "ActivityCard" ascii //weight: 1
        $x_1_5 = "mandatoryNotifications" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AR_2147889553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AR!MTB"
        threat_id = "2147889553"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Lcom/example/smslistenerapp" ascii //weight: 5
        $x_5_2 = "Lcom/example/myapplication/SmsSuccessActivity" ascii //weight: 5
        $x_5_3 = "Lcom/browser/web23/SmsReceiverActivity" ascii //weight: 5
        $x_5_4 = "Lcom/google/go/SmsReceiver" ascii //weight: 5
        $x_1_5 = "ttps://www.snetapis.com/api/" ascii //weight: 1
        $x_1_6 = "sms-test/index.php" ascii //weight: 1
        $x_1_7 = "this_sms_receiver_app" ascii //weight: 1
        $x_1_8 = "SmsReceiverActivity" ascii //weight: 1
        $x_1_9 = "/install.php" ascii //weight: 1
        $x_1_10 = "ttps://www.comnetorginfo.com/data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SAgnt_AS_2147892401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AS!MTB"
        threat_id = "2147892401"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.wsys.sync" ascii //weight: 5
        $x_1_2 = "uploadFriendData" ascii //weight: 1
        $x_5_3 = "wsys_ds" ascii //weight: 5
        $x_1_4 = "UploadChatManager" ascii //weight: 1
        $x_1_5 = "EncryptUpdateData" ascii //weight: 1
        $x_1_6 = "uploadTextMessageToService" ascii //weight: 1
        $x_1_7 = "wsys_dsdoSyncPhoneBook" ascii //weight: 1
        $x_1_8 = "wsys_ds updateUserInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SAgnt_AT_2147893581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AT!MTB"
        threat_id = "2147893581"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "messSendSms" ascii //weight: 1
        $x_1_2 = "LinkHayAndroidActivity" ascii //weight: 1
        $x_1_3 = "heardSms7" ascii //weight: 1
        $x_1_4 = "totalsms.txt" ascii //weight: 1
        $x_1_5 = "countSendSms" ascii //weight: 1
        $x_1_6 = "sendSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AU_2147895677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AU!MTB"
        threat_id = "2147895677"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sys_send_contents" ascii //weight: 1
        $x_1_2 = "sys_saved_contents" ascii //weight: 1
        $x_1_3 = "SetTnkTracker" ascii //weight: 1
        $x_1_4 = "/affmob.tornika.com/service_lib.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AV_2147895679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AV!MTB"
        threat_id = "2147895679"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.andreszs.smsreceive" ascii //weight: 1
        $x_1_2 = "SMSCommunicator" ascii //weight: 1
        $x_1_3 = "/api/usersms/createv2?userId=" ascii //weight: 1
        $x_1_4 = "ComposeSMSActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AW_2147899022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AW!MTB"
        threat_id = "2147899022"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "send_data" ascii //weight: 1
        $x_1_2 = "com/WSCube/ControlPanel/SmsService" ascii //weight: 1
        $x_1_3 = "performPostCall" ascii //weight: 1
        $x_1_4 = "CodeFromPanel" ascii //weight: 1
        $x_1_5 = "sended_code2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AX_2147899828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AX!MTB"
        threat_id = "2147899828"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/Kalinc/Control/SmsService" ascii //weight: 1
        $x_1_2 = "CodeFromPanel" ascii //weight: 1
        $x_1_3 = "getDeviceName" ascii //weight: 1
        $x_1_4 = "code_from_mail" ascii //weight: 1
        $x_1_5 = "performGetCall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AY_2147902067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AY!MTB"
        threat_id = "2147902067"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.software.app" ascii //weight: 1
        $x_1_2 = "sms_text" ascii //weight: 1
        $x_1_3 = "DeviceRegistrar" ascii //weight: 1
        $x_1_4 = "SENT_SMS_NUMBER_KEY" ascii //weight: 1
        $x_1_5 = "OFFERT_ACTIVITY" ascii //weight: 1
        $x_1_6 = "areInstalledAndActedLinksEquals" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_SAgnt_AZ_2147904544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.AZ!MTB"
        threat_id = "2147904544"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSToMapActivity" ascii //weight: 1
        $x_1_2 = "/sdcard/BikingData/myloc" ascii //weight: 1
        $x_1_3 = "sms_selectContact" ascii //weight: 1
        $x_1_4 = "poi_sms_lat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_BA_2147904545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.BA!MTB"
        threat_id = "2147904545"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHCameraSurface" ascii //weight: 1
        $x_1_2 = "KeonaDemoAct" ascii //weight: 1
        $x_1_3 = "ariacrypt_enable" ascii //weight: 1
        $x_1_4 = "/apk/pdaid.txt" ascii //weight: 1
        $x_1_5 = "nonpay.co.kr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_BC_2147906018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.BC!MTB"
        threat_id = "2147906018"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deliverBR1" ascii //weight: 1
        $x_1_2 = "sentBR1" ascii //weight: 1
        $x_1_3 = "/sdcard/downloadedfile.apk" ascii //weight: 1
        $x_1_4 = "vn/adflex/ads" ascii //weight: 1
        $x_1_5 = "AdsService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_BD_2147906019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.BD!MTB"
        threat_id = "2147906019"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "android.php?device_b=" ascii //weight: 1
        $x_1_2 = "number.php?n=" ascii //weight: 1
        $x_1_3 = "lume/activity/app" ascii //weight: 1
        $x_1_4 = "sms.html" ascii //weight: 1
        $x_1_5 = "goMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_BE_2147906932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.BE!MTB"
        threat_id = "2147906932"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/my/newproject39" ascii //weight: 1
        $x_1_2 = "TelegramImageUploader" ascii //weight: 1
        $x_1_3 = "/sendPhoto" ascii //weight: 1
        $x_1_4 = "startLogging" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_BF_2147908989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.BF!MTB"
        threat_id = "2147908989"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getSMSCount" ascii //weight: 1
        $x_1_2 = "getPhone" ascii //weight: 1
        $x_1_3 = "MessageSender" ascii //weight: 1
        $x_1_4 = "com/soft/android/appinstaller" ascii //weight: 1
        $x_1_5 = "rules_activity.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_BG_2147916714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.BG!MTB"
        threat_id = "2147916714"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendPhoneInformationAlarm" ascii //weight: 1
        $x_1_2 = "FIND SMS LOG CONDITION=" ascii //weight: 1
        $x_1_3 = "SendPhoneTimeDiffAlarm" ascii //weight: 1
        $x_1_4 = "MaskActivity" ascii //weight: 1
        $x_1_5 = "replysendsmsinfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_BH_2147926122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.BH!MTB"
        threat_id = "2147926122"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 20 30 00 20 00 6e 10 31 00 00 00 12 13 12 04 12 05 07 10 07 21 08 02 15 00 77 06 66 00 00 00 0c 09 71 10 65 00 07 00 0c 08 1a 0a 00 00 12 1b 12 1c 12 0d 12 0e 16 0f 01 00 13 11 02 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 06 02 04 1a 07 59 02 70 20 03 00 7e 00 0c 07 6e 20 48 00 76 00 0a 07 38 07 62 00 6e 10 15 00 0e 00 0c 07 6e 20 27 00 67 00 0c 06 6e 10 36 00 06 00 0a 07 23 78 bf 01 6e 20 38 00 86 00 6e 10 37 00 06 00 1a 06 5c 02 70 20 03 00 6e 00 0c 06 71 10 39 00 06 00 0a 06 23 79 bf 01 01 1a 35 7a 0b 00 48 0b 08 0a b7 6b 8d bb 4f 0b 09 0a d8 0a 0a 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgnt_CA_2147943674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgnt.CA!MTB"
        threat_id = "2147943674"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 00 6e 10 81 01 00 00 0c 00 1c 01 9c 00 1a 02 03 54 12 13 23 34 3d 16 1c 05 21 0f 12 06 4d 05 04 06 6e 30 67 59 21 04 0c 01 23 32 40 16 4d 08 02 06 6e 30 d6 5a 01 02 0c 00 1f 00 f0 0e 6e 10 2b 59 00 00 0a 07}  //weight: 1, accuracy: High
        $x_1_2 = {22 00 52 01 6e 10 0e 01 02 00 0c 01 70 20 fd 06 10 00 22 01 87 04 70 20 ed 1f 21 00 6e 20 07 07 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

