rule TrojanSpy_AndroidOS_Banker_A_2147724616_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.A"
        threat_id = "2147724616"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "permission_req_code_device_admin" ascii //weight: 1
        $x_1_2 = "permission_req_code_sms_" ascii //weight: 1
        $x_1_3 = "val$demoDeviceAdmin" ascii //weight: 1
        $x_1_4 = "session_gcm_reg_delivery" ascii //weight: 1
        $x_1_5 = {53 65 74 4a 61 76 61 53 63 72 69 70 74 45 6e 61 62 6c 65 64 ?? ?? 53 75 70 65 72 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
        $x_1_6 = "removeActiveAdmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_A_2147744541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.A!MTB"
        threat_id = "2147744541"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AndroidBot/Screencast" ascii //weight: 3
        $x_3_2 = "android:id/sms_short_code_remember_choice_checkbox" ascii //weight: 3
        $x_1_3 = "tt9.page.link/XktS" ascii //weight: 1
        $x_1_4 = "InjectComponent" ascii //weight: 1
        $x_1_5 = "request_credentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Banker_A_2147744541_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.A!MTB"
        threat_id = "2147744541"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "omhachtaigh::[is]virkja::[es]activar::[it]attivare::[kk]" ascii //weight: 1
        $x_1_2 = "ACC::onAccessibilityEvent: left_button" ascii //weight: 1
        $x_1_3 = "Access=1Perm=1" ascii //weight: 1
        $x_1_4 = "Ccom.google.android.gms.security.settings.VerifyAppsSettingsActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_C_2147745128_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.C!MTB"
        threat_id = "2147745128"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/BgService;" ascii //weight: 2
        $x_1_2 = "SmsListener" ascii //weight: 1
        $x_1_3 = "handleIncomingSMS" ascii //weight: 1
        $x_1_4 = "calltransferredlist" ascii //weight: 1
        $x_1_5 = "callcontacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Banker_C_2147745128_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.C!MTB"
        threat_id = "2147745128"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Plugs.startBankingBlocker" ascii //weight: 1
        $x_1_2 = "/system_update.apk" ascii //weight: 1
        $x_1_3 = "bank.html" ascii //weight: 1
        $x_1_4 = "hideNotification" ascii //weight: 1
        $x_1_5 = "msgListSend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_D_2147745792_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.D!MTB"
        threat_id = "2147745792"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lorg/slempo/service/activities/CvcPopup;" ascii //weight: 1
        $x_1_2 = "CreditCardNumberEditText" ascii //weight: 1
        $x_1_3 = "intercept_sms_start" ascii //weight: 1
        $x_1_4 = "getInstalledAppsList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_B_2147751806_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.B"
        threat_id = "2147751806"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JavmavService" ascii //weight: 2
        $x_2_2 = "VoacActivity" ascii //weight: 2
        $x_1_3 = "/MasReceiver;" ascii //weight: 1
        $x_1_4 = "/dwesReceiver;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Banker_C_2147751941_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.C"
        threat_id = "2147751941"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/KsaApplication;" ascii //weight: 3
        $x_3_2 = "/KvService;" ascii //weight: 3
        $x_3_3 = "/VcActivity;" ascii //weight: 3
        $x_3_4 = "/VsReceiver;" ascii //weight: 3
        $x_2_5 = "asc2V0Q29tcG9u" ascii //weight: 2
        $x_1_6 = "ZW50RW5hYmxlZFNldHRpbmc=" ascii //weight: 1
        $x_2_7 = "1ZGFsdmlrLnN5c3R" ascii //weight: 2
        $x_1_8 = "lbS5EZXhDbGFzc0xvYWRlcg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Banker_E_2147753185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.E!MTB"
        threat_id = "2147753185"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/xhelperdata.jar" ascii //weight: 2
        $x_1_2 = "/xhelperdata.dex" ascii //weight: 1
        $x_1_3 = "SO_001" ascii //weight: 1
        $x_1_4 = "com.mufc." ascii //weight: 1
        $x_1_5 = "lp.cooktracking.com/v1/ls/get" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Banker_F_2147763037_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.F!MTB"
        threat_id = "2147763037"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "basdvvSATATwtcdsa" ascii //weight: 2
        $x_2_2 = "bbavoPrssw" ascii //weight: 2
        $x_1_3 = "track_sms" ascii //weight: 1
        $x_1_4 = "findAccessibilityNodeInfosByViewId" ascii //weight: 1
        $x_1_5 = "lockscr" ascii //weight: 1
        $x_1_6 = "actallinj" ascii //weight: 1
        $x_1_7 = "instapps" ascii //weight: 1
        $x_1_8 = "keylog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Banker_F_2147763037_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.F!MTB"
        threat_id = "2147763037"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Spam/ServiceSenderSpamSMS" ascii //weight: 1
        $x_1_2 = "ActivityFakeAppStart" ascii //weight: 1
        $x_1_3 = "ActivityScreenLocker" ascii //weight: 1
        $x_1_4 = "ServiceCryptFiles" ascii //weight: 1
        $x_1_5 = "ServicePlayProtectToast" ascii //weight: 1
        $x_1_6 = "PushInjection" ascii //weight: 1
        $x_1_7 = "GetSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_G_2147763399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.G!MTB"
        threat_id = "2147763399"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lkhjjhkghkg/yulyuuyklyuky/" ascii //weight: 2
        $x_2_2 = "eryeryeryeryer.java" ascii //weight: 2
        $x_1_3 = "Run_Necessary_Injection" ascii //weight: 1
        $x_1_4 = "Download_All_SMS" ascii //weight: 1
        $x_1_5 = "Your phone has been blocked" ascii //weight: 1
        $x_1_6 = "Urgent message!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Banker_H_2147768114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.H!MTB"
        threat_id = "2147768114"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 6c 64 5f 73 74 61 72 74 5f 69 6e 6a 00}  //weight: 1, accuracy: High
        $x_1_2 = "app_inject" ascii //weight: 1
        $x_1_3 = ".Logs com.google.android.apps.authenticator2:" ascii //weight: 1
        $x_1_4 = "||youNeedMoreResources||" ascii //weight: 1
        $x_1_5 = "findAccessibilityNodeInfosByViewId" ascii //weight: 1
        $x_1_6 = "performGlobalAction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_I_2147769545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.I!MTB"
        threat_id = "2147769545"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.bananasplit.shop" ascii //weight: 1
        $x_1_2 = "com/kitkagames/fallbuddies" ascii //weight: 1
        $x_1_3 = "hasSmsServices" ascii //weight: 1
        $x_1_4 = "mobileNumberPortableRegion_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_I_2147769545_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.I!MTB"
        threat_id = "2147769545"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/byl/sms/SplashActivity" ascii //weight: 1
        $x_1_2 = "888ccb.com/api/index/information" ascii //weight: 1
        $x_1_3 = "shaodetiankong.club/api/index/sms" ascii //weight: 1
        $x_1_4 = "pay_password" ascii //weight: 1
        $x_1_5 = "LOGIN_CHECK_ISPASS" ascii //weight: 1
        $x_1_6 = "smSApplication" ascii //weight: 1
        $x_1_7 = "uploadSmSMethod" ascii //weight: 1
        $x_1_8 = "888ccb.com/api/index/sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_K_2147777447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.K!MTB"
        threat_id = "2147777447"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f [0-32] 2f 42 61 6e 6b 3b}  //weight: 2, accuracy: Low
        $x_2_2 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f [0-32] 2f 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 3b}  //weight: 2, accuracy: Low
        $x_1_3 = "/SmsReceiver;" ascii //weight: 1
        $x_1_4 = "findAccessibilityNodeInfosByText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AJ_2147780685_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AJ!MTB"
        threat_id = "2147780685"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "load_sms_mass.php" ascii //weight: 1
        $x_1_2 = "upload_sms" ascii //weight: 1
        $x_1_3 = "root_phone" ascii //weight: 1
        $x_1_4 = "set_card.php" ascii //weight: 1
        $x_1_5 = "bankwest.mobile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AD_2147781388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AD!MTB"
        threat_id = "2147781388"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "phonelistener" ascii //weight: 1
        $x_1_2 = "bankinid" ascii //weight: 1
        $x_1_3 = "/mnt/sdcard/NPKI" ascii //weight: 1
        $x_1_4 = "liujun199067@126.com" ascii //weight: 1
        $x_1_5 = "NHAcountInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_J_2147787558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.J!MTB"
        threat_id = "2147787558"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {12 00 21 81 23 11 c7 00 01 02 01 23 21 84 35 40 35 00 d8 02 02 01 d5 22 ff 00 54 74 12 00 48 04 04 02 b0 43 d5 33 ff 00 54 74 12 00 48 04 04 03 54 75 12 00 54 76 12 00 48 06 06 02 4f 06 05 03 54 75 12 00 4f 04 05 02 54 74 12 00 48 04 04 02 54 75 12 00 48 05 05 03 b0 54 d5 44 ff 00 54 75 12 00 48 04 05 04 48 05 08 00 b7 54 8d 44 4f 04 01 00 d8 00 00 01 28 cb 11 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_GV_2147787746_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.GV!MTB"
        threat_id = "2147787746"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "logicbankbot/crypto/" ascii //weight: 2
        $x_1_2 = "/sendmessage?chat_id=" ascii //weight: 1
        $x_1_3 = "Enable Device Admin For Update" ascii //weight: 1
        $x_1_4 = "forward_sms_all" ascii //weight: 1
        $x_1_5 = "bot/getUpdates" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Banker_L_2147807683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.L!MTB"
        threat_id = "2147807683"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 01 71 20 ?? ?? 19 00 0c 02 21 23 13 04 0b 00 37 43 40 00 12 33 23 33 ?? ?? 13 05 08 00 48 06 02 05 4f 06 03 01 12 16 13 07 09 00 48 07 02 07 4f 07 03 06 13 06 0a 00 48 06 02 06 12 27 4f 06 03 07 22 06 ?? ?? 62 08 ?? ?? 70 30 ?? ?? 36 08 1a 03 ?? ?? 6e 20 ?? ?? 36 00 0a 03 38 03 1a 00 22 03 ?? ?? 70 50 ?? ?? 23 51 71 10 ?? ?? 00 00 0c 00 6e 30 ?? ?? 70 03 22 01 ?? ?? 21 23 b1 43 6e 40 ?? ?? 20 34 0c 00 70 20 ?? ?? 01 00 07 19 11 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_XO_2147807958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.XO"
        threat_id = "2147807958"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 02 05 04 35 21 0f 00 62 02 [0-2] 90 03 04 01 4a 02 02 03 b7 62 8e 22 50 02 00 01 d8 01 01 01 28 f0}  //weight: 1, accuracy: Low
        $x_1_2 = "PeriodicJobService" ascii //weight: 1
        $x_1_3 = "InjAccessibilityService" ascii //weight: 1
        $x_1_4 = "ScreencastService" ascii //weight: 1
        $x_1_5 = "LockerActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_S_2147808733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.S!MTB"
        threat_id = "2147808733"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendsCallNumberToServer" ascii //weight: 1
        $x_1_2 = "startSforSend" ascii //weight: 1
        $x_1_3 = "gating.php" ascii //weight: 1
        $x_1_4 = "sendSRecRequest" ascii //weight: 1
        $x_1_5 = "lkrishtifaa.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_M_2147808784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.M!MTB"
        threat_id = "2147808784"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 03 71 10 ?? ?? 04 00 0a 05 35 53 ?? ?? 71 20 ?? ?? 34 00 0c 05 1f 05 28 00 12 06 13 07 64 00 35 76 0f 00 21 57 35 76 0c 00 48 07 05 06 d7 77 88 00 8d 77 4f 07 05 06 d8 06 06 01 28 f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_I_2147808882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.I"
        threat_id = "2147808882"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "emplye_adap" ascii //weight: 1
        $x_1_2 = "calls_all_sent" ascii //weight: 1
        $x_1_3 = "Sorry app can't without all permissions" ascii //weight: 1
        $x_1_4 = "login_kotak_unsuccessfull" ascii //weight: 1
        $x_1_5 = "all_sms_received" ascii //weight: 1
        $x_1_6 = "DATA_app_alert" ascii //weight: 1
        $x_1_7 = "<>sms_app" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_O_2147809016_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.O!MTB"
        threat_id = "2147809016"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 01 21 72 35 21 ?? ?? 71 10 ?? ?? 06 00 0a 02 d8 02 02 01 d4 22 00 01 59 62 0d 00 71 10 82 00 06 00 0a 02 71 10 84 00 06 00 0c 03 71 10 85 00 06 00 0a 04 44 05 03 04 b0 52 d4 22 00 01 59 62 0e 00 71 10 ?? ?? 06 00 0a 02 71 40 ?? ?? 46 32 71 10 ?? ?? 06 00 0c 02 71 10 ?? ?? 06 00 0a 03 44 03 02 03 71 10 ?? ?? 06 00 0a 04 44 04 02 04 b0 43 d4 33 00 01 44 02 02 03 48 03 07 01 b7 32 8d 22 4f 02 00 01 d8 01 01 01 28 bc 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_N_2147812782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.N!MTB"
        threat_id = "2147812782"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 00 1a 03 00 00 1a 02 00 00 01 01 13 04 0f 00 34 41 24 00 22 01 ?? ?? 6e 10 ?? ?? 08 00 0a 04 db 04 04 02 70 20 ?? ?? 41 00 6e 10 ?? ?? 08 00 0a 04 3c 04 ?? ?? 6e 10 ?? ?? 01 00 0c 01 21 13 6e 10 ?? ?? 02 00 0a 04 34 30 54 00 22 00 ?? ?? 70 20 ?? ?? 10 00 11 00 22 04 ?? ?? 70 10 ?? ?? 04 00 6e 20 ?? ?? 34 00 0c 03 71 10 ?? ?? 01 00 0c 04 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 03 00 0c 03 22 04 ?? ?? 70 10 ?? ?? 04 00 6e 20 ?? ?? 24 00 0c 02 71 00 ?? ?? 00 00 0b 04 13 06 0a 00 83 66 cd 64 8a 44 b7 14 6e 20 ?? ?? 42 00 0c 02 6e 10 ?? ?? 02 00 0c 02 d8 01 01 01 28 a8}  //weight: 2, accuracy: Low
        $x_1_2 = "eu/chainfire/libsuperuser/Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_P_2147814197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.P!MTB"
        threat_id = "2147814197"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/mille/mgx/getdefaultsms_activity" ascii //weight: 1
        $x_1_2 = "activity_keypress" ascii //weight: 1
        $x_1_3 = "puxaSMSLoop" ascii //weight: 1
        $x_1_4 = "smspush_BR" ascii //weight: 1
        $x_1_5 = "bit.do/activacionn" ascii //weight: 1
        $x_1_6 = "me_device.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_R_2147815316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.R!MTB"
        threat_id = "2147815316"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 21 0f 00 62 02 ?? 04 ?? 03 04 01 4a 02 02 03 b7 62 8e 22 50 02 00 01 d8 01 01 01 28 f0}  //weight: 1, accuracy: Low
        $x_1_2 = "performAction" ascii //weight: 1
        $x_1_3 = "performGlobalAction" ascii //weight: 1
        $x_1_4 = "setAutoCancel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_Q_2147816008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.Q!MTB"
        threat_id = "2147816008"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sms-super-rat.site/indici_functions.php" ascii //weight: 1
        $x_1_2 = "uploadMessage" ascii //weight: 1
        $x_1_3 = "sendListApp" ascii //weight: 1
        $x_1_4 = "OutgoingCallList" ascii //weight: 1
        $x_1_5 = "forwardingToApk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AN_2147821980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AN!MTB"
        threat_id = "2147821980"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/DummyAccessibility;" ascii //weight: 1
        $x_1_2 = "/Loader;" ascii //weight: 1
        $x_1_3 = "com.raccoon.Accessibility" ascii //weight: 1
        $x_1_4 = "/DEX_API.apk" ascii //weight: 1
        $x_1_5 = "LoadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_U_2147822294_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.U!MTB"
        threat_id = "2147822294"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/biyitunixiko/populolo" ascii //weight: 1
        $x_1_2 = "c29zaV9zb3Npc29uX19fXw==" ascii //weight: 1
        $x_1_3 = "com.piwitiseyino.vitapeka.dicazeyaviso" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AF_2147822841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AF!MTB"
        threat_id = "2147822841"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ehw/jxekwxjshyCu/iuskhuiCi" ascii //weight: 1
        $x_1_2 = "mmsc.monternet.com" ascii //weight: 1
        $x_1_3 = "tr/servlets/mms" ascii //weight: 1
        $x_1_4 = "lockNow" ascii //weight: 1
        $x_1_5 = "resetPassword" ascii //weight: 1
        $x_1_6 = "ehw/jxekwxjshyCu/iuskhuiCi/dejyvysqjyedi/pqhnHuqtHusuyluh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AM_2147827427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AM!MTB"
        threat_id = "2147827427"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "textSPAM" ascii //weight: 1
        $x_1_2 = "spamSMS" ascii //weight: 1
        $x_1_3 = "keys.log" ascii //weight: 1
        $x_1_4 = "killBot -> Commands" ascii //weight: 1
        $x_1_5 = "indexSMSSPAM" ascii //weight: 1
        $x_1_6 = "START RECORD SOUND" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AG_2147827596_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AG!MTB"
        threat_id = "2147827596"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "niouhpkaefbz/qkwehixqqootmoqhhbjh" ascii //weight: 1
        $x_1_2 = "naiebrvl/eojiusokhflb" ascii //weight: 1
        $x_1_3 = "vcojqbfbvmvwe/jdnmjqllm" ascii //weight: 1
        $x_1_4 = "bkhrwefetnbzvxgn/rxmedyhoqox" ascii //weight: 1
        $x_1_5 = "/dev/cpuctl/tasks" ascii //weight: 1
        $x_1_6 = "onTaskRemoved" ascii //weight: 1
        $x_1_7 = "isAdminActive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_B_2147827626_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.B!MTB"
        threat_id = "2147827626"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "startSmsInterceptionCommandExecuted" ascii //weight: 1
        $x_1_2 = "getCallListCommand" ascii //weight: 1
        $x_1_3 = "launchAppCommandExecuted" ascii //weight: 1
        $x_1_4 = "bot_id" ascii //weight: 1
        $x_1_5 = "sendDataToServer" ascii //weight: 1
        $x_1_6 = "setAdminCommand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_O_2147830261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.O"
        threat_id = "2147830261"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "all_sms_received" ascii //weight: 1
        $x_1_2 = "DATA_RECEIVED_ALERT" ascii //weight: 1
        $x_1_3 = "<>Silent_done" ascii //weight: 1
        $x_1_4 = "all_call_received" ascii //weight: 1
        $x_1_5 = "<>msg<>YES IS ONLINE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_W_2147831778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.W!MTB"
        threat_id = "2147831778"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {92 04 01 03 d8 05 04 02 6e 30 94 03 46 05 0c 04 13 05 10 00 71 20 79 03 54 00 0c 04 6e 10 72 03 04 00 0a 04 4f 04 02 03 d8 03 03 01 28 e8}  //weight: 1, accuracy: High
        $x_1_2 = {6f 30 e7 05 10 02 54 02 ad 02 6e 20 c6 00 21 00 0e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_V_2147832532_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.V!MTB"
        threat_id = "2147832532"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/sspl/app/Activities" ascii //weight: 1
        $x_1_2 = "pginsarholgurugram.xyz/getlocation.php" ascii //weight: 1
        $x_1_3 = "pginsarholgurugram.xyz/getsms.php" ascii //weight: 1
        $x_1_4 = ".xyz/getcall.php" ascii //weight: 1
        $x_1_5 = ".xyz/getaudio.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_X_2147832913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.X!MTB"
        threat_id = "2147832913"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GPhoneReciver" ascii //weight: 1
        $x_1_2 = "phone_detail" ascii //weight: 1
        $x_1_3 = "banklist" ascii //weight: 1
        $x_1_4 = "DeAdminReciver" ascii //weight: 1
        $x_1_5 = "Lcom/vivaclao/syncservice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_Y_2147833124_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.Y!MTB"
        threat_id = "2147833124"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mt/work/activity/LoginAct" ascii //weight: 1
        $x_1_2 = "AlbumService" ascii //weight: 1
        $x_1_3 = "LocalCallMt" ascii //weight: 1
        $x_1_4 = "LocalMsgMt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AB_2147833939_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AB!MTB"
        threat_id = "2147833939"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6d 2f 61 70 70 2f 6d 61 6e 61 67 65 72 2f [0-32] 4d 61 69 6e 41 63 74 69 76 69 74 79}  //weight: 1, accuracy: Low
        $x_1_2 = "uploaddata" ascii //weight: 1
        $x_1_3 = "getRunningTasks" ascii //weight: 1
        $x_1_4 = "card_number" ascii //weight: 1
        $x_1_5 = "savepersonaldetails_stepfirst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_Z_2147834046_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.Z!MTB"
        threat_id = "2147834046"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 12 21 b3 10 23 02 62 01 12 03 35 03 19 00 92 04 01 03 d8 05 04 02 6e 30 ?? ?? 46 05 0c 04 13 05 10 00 71 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0a 04 4f 04 02 03 d8 03 03 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AA_2147835105_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AA!MTB"
        threat_id = "2147835105"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "backupSMS" ascii //weight: 1
        $x_1_2 = "uploadMobileInfo" ascii //weight: 1
        $x_1_3 = "reuploadCall" ascii //weight: 1
        $x_1_4 = "BankDetailActivity" ascii //weight: 1
        $x_1_5 = "trace_password" ascii //weight: 1
        $x_1_6 = "MoblieController" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AE_2147835605_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AE!MTB"
        threat_id = "2147835605"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "swapSmsMenager" ascii //weight: 1
        $x_1_2 = "startClearCash" ascii //weight: 1
        $x_1_3 = "callCapablePhoneAccounts" ascii //weight: 1
        $x_1_4 = "checkCallingOrSelfPermission" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AH_2147837893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AH!MTB"
        threat_id = "2147837893"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "forwardContent" ascii //weight: 1
        $x_1_2 = "/save_sms.php" ascii //weight: 1
        $x_1_3 = "mysmsmanager" ascii //weight: 1
        $x_1_4 = "forwardNumber" ascii //weight: 1
        $x_1_5 = "000webhostapp.com/otp.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AI_2147837900_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AI!MTB"
        threat_id = "2147837900"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bank12.php?m=Api&a=Sms&imsi=" ascii //weight: 1
        $x_1_2 = "SMSReceiver" ascii //weight: 1
        $x_1_3 = "setComponentEnabledSetting" ascii //weight: 1
        $x_1_4 = "bankcard" ascii //weight: 1
        $x_1_5 = "bankpw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AK_2147838807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AK!MTB"
        threat_id = "2147838807"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 72 35 21 30 00 52 62 ?? ?? d8 02 02 01 d4 22 00 01 59 62 ?? ?? 52 63 ?? ?? 54 64 ?? ?? 44 05 04 02 b0 53 d4 33 00 01 59 63 ?? ?? 70 40 ?? ?? 26 43 54 62 ?? ?? 52 63 ?? ?? 44 03 02 03 52 64 ?? ?? 44 04 02 04 b0 43 d4 33 00 01 44 02 02 03 48 03 07 01 b7 32 8d 22 4f 02 00 01 d8 01 01 01}  //weight: 1, accuracy: Low
        $x_1_2 = "notif_open" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AL_2147841566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AL!MTB"
        threat_id = "2147841566"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "devil/sk/SmsReceiver" ascii //weight: 5
        $x_5_2 = "getBBVAPassword" ascii //weight: 5
        $x_1_3 = "checkCallingOrSelfPermission" ascii //weight: 1
        $x_1_4 = "checkReadAndReceiveAndSendSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Banker_BD_2147844325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.BD!MTB"
        threat_id = "2147844325"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "interceptNotification" ascii //weight: 1
        $x_1_2 = "sendKeylogs" ascii //weight: 1
        $x_1_3 = "dynamicsocket" ascii //weight: 1
        $x_1_4 = "DeviceAdminAdd" ascii //weight: 1
        $x_1_5 = "enabled_accessibility_services" ascii //weight: 1
        $x_1_6 = "isDebuggerConnected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AO_2147844884_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AO!MTB"
        threat_id = "2147844884"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/Transiction" ascii //weight: 1
        $x_1_2 = {63 6f 6d 2f [0-8] 2f 73 6d 73 74 65 73 74}  //weight: 1, accuracy: Low
        $x_1_3 = "hideLauncherIcon" ascii //weight: 1
        $x_1_4 = "executeDelayed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AP_2147846769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AP!MTB"
        threat_id = "2147846769"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6d 2f 61 70 70 2f [0-8] 2f 41 63 74 69 76 69 74 79 46 69 6c 74 65 72 4d 67 72}  //weight: 1, accuracy: Low
        $x_1_2 = "/ScreenShotService" ascii //weight: 1
        $x_1_3 = "onStartTrackingTouch" ascii //weight: 1
        $x_1_4 = "OrientationEventListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AQ_2147913288_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AQ!MTB"
        threat_id = "2147913288"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendSmstoerver" ascii //weight: 1
        $x_1_2 = "com/mycard/icv" ascii //weight: 1
        $x_1_3 = "SmsRepository" ascii //weight: 1
        $x_1_4 = "rrdd.co.in/admin_panel/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Banker_AR_2147946730_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Banker.AR!MTB"
        threat_id = "2147946730"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 1c ff ff a2 1c 1c 04 18 1e 00 00 ff ff 00 00 ff ff a2 1c 1c 1e a0 1a 1a 1c 13 02 10 00 a4 1a 1a 02 05 00 1a 00 84 02 8f 28 60 02 8e 00 60 0a ad 00 d2 aa 3d e9 b6 a2 3c 02 08 00 08 02 16 00 02 11 08 00}  //weight: 1, accuracy: High
        $x_1_2 = {22 04 a1 00 70 10 fa 03 04 00 6e 20 fc 03 24 00 0c 02 71 00 d8 03 00 00 0b 04 13 06 0a 00 83 66 cd 64 8a 44 b7 04 6e 20 fb 03 42 00 0c 02 6e 10 fd 03 02 00 0c 02 d8 00 00 01}  //weight: 1, accuracy: High
        $x_1_3 = {6e 20 ea 03 08 00 0a 05 6e 20 f1 03 53 00 0a 05 e0 05 05 04 d8 06 00 01 6e 20 ea 03 68 00 0a 06 6e 20 f1 03 63 00 0a 06 b6 65 6e 20 6f 03 54 00 d8 00 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

