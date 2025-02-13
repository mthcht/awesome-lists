rule Trojan_AndroidOS_FakeApp_H_2147773440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.H!MTB"
        threat_id = "2147773440"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 6c 69 78 6f 6e 6c 69 6e 65 [0-1] 2f 63 68 65 63 6b 53 65 72 76 65 72 41 6e 64 45 78 65 63 75 74 65 3b}  //weight: 1, accuracy: Low
        $x_1_2 = {66 6c 69 78 6f 6e 6c 69 6e 65 [0-1] 2f 54 68 65 4a 6f 62 43 68 72 6f 6d 69 75 6d 3b}  //weight: 1, accuracy: Low
        $x_1_3 = "get data from server" ascii //weight: 1
        $x_1_4 = "browser_url" ascii //weight: 1
        $x_1_5 = "com.android.chrome/com.android.chrome.Main" ascii //weight: 1
        $x_1_6 = "com.whatsapp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_FakeApp_K_2147779247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.K!MTB"
        threat_id = "2147779247"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/wagd/gg/MyService;" ascii //weight: 2
        $x_2_2 = "/update/update.conf" ascii //weight: 2
        $x_1_3 = "load64Data bytes" ascii //weight: 1
        $x_1_4 = "getThisAppArch" ascii //weight: 1
        $x_1_5 = "MobclickRT" ascii //weight: 1
        $x_1_6 = "/system/app/Kinguser.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_FakeApp_T_2147780773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.T!MTB"
        threat_id = "2147780773"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lookpink.xyz/landing.php/?app" ascii //weight: 1
        $x_1_2 = "AutoResponder" ascii //weight: 1
        $x_1_3 = "inside sendReply" ascii //weight: 1
        $x_1_4 = "Apply New Pink* Look on Your Whatsapp And Enjoy Whats app new Features" ascii //weight: 1
        $x_1_5 = ".xyz/?whatsapp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_D_2147807996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.D"
        threat_id = "2147807996"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LseC/nC/sxqhwu/XeBtpuiiqwu" ascii //weight: 1
        $x_1_2 = "AnalyseData BBXRUrl" ascii //weight: 1
        $x_1_3 = "HanldeRule number null data null" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_B_2147816082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.B!MTB"
        threat_id = "2147816082"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/shiqi/qccex/login/FlashActivity" ascii //weight: 1
        $x_1_2 = "GetCustomerServiceLinkRequest" ascii //weight: 1
        $x_1_3 = "refreshAccessToken" ascii //weight: 1
        $x_1_4 = "saveTokenInfo" ascii //weight: 1
        $x_1_5 = "hideFakeStatusBar" ascii //weight: 1
        $x_1_6 = "saveShowBuyCoinTips" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_FakeApp_C_2147828234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.C!MTB"
        threat_id = "2147828234"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getCallsPerHost" ascii //weight: 1
        $x_1_2 = "upLoadSMSList" ascii //weight: 1
        $x_1_3 = "getLoginPhone" ascii //weight: 1
        $x_1_4 = "uploadContacts" ascii //weight: 1
        $x_1_5 = "cancelAllNotifications" ascii //weight: 1
        $x_1_6 = "uploadLocation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_FakeApp_D_2147828434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.D!MTB"
        threat_id = "2147828434"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "adobeflashplayer.mobi" ascii //weight: 10
        $x_10_2 = "24-business.com/" ascii //weight: 10
        $x_5_3 = "download.macromedia." ascii //weight: 5
        $x_5_4 = "wimaxInfo" ascii //weight: 5
        $x_1_5 = "emailIntent2" ascii //weight: 1
        $x_1_6 = "hasmobogenie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_FakeApp_L_2147828881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.L!MTB"
        threat_id = "2147828881"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 00 08 00 22 00 [0-6] 50 00 11 00 d8 06 02 ff 6e 20 ?? ?? 28 00 0a 00 6e 20 ?? ?? 34 00 0a 07 b7 70 df 00 00 ?? ?? 00 50 00 05 02 3a 06 ea ff 6e 20 ee 46 68 00 0a 00 6e 20 ?? ?? 34 00 0a 02 b7 20 df 00 ?? ?? 8e 07 d8 02 06 ff d8 00 03 ff 50 07 05 06 3b 00 03 00 01 10 01 03 01 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_O_2147828882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.O!MTB"
        threat_id = "2147828882"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 00 08 00 22 00 ?? ?? ?? ?? ?? 46 50 00 11 00 d8 06 02 ff 6e 20 ?? 46 28 00 0a 00 6e 20 ?? 46 34 00 0a 07 b7 70 df 00 00 ?? 8e 00 50 00 05 02 3a 06 ea ff 6e 20 ?? 46 68 00 0a 00 6e 20 ?? 46 34 00 0a 02 b7 20 df 00 00 ?? 8e 07 d8 02 06 ff d8 00 03 ff 50 07 05 06 3b 00 03 00 01 10 01 03 01 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_M_2147828883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.M!MTB"
        threat_id = "2147828883"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "seC/myvyvhuu/Cuiiudwuh" ascii //weight: 3
        $x_3_2 = "com/onlinevoice/playerapp" ascii //weight: 3
        $x_3_3 = "seC/qdtheyt/leBBuO" ascii //weight: 3
        $x_1_4 = "file.delete" ascii //weight: 1
        $x_1_5 = "setjavascriptenabled" ascii //weight: 1
        $x_1_6 = "uploadMsg" ascii //weight: 1
        $x_1_7 = "xqdtBupuiiqwu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_FakeApp_F_2147828948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.F!MTB"
        threat_id = "2147828948"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsSuccessActivity" ascii //weight: 1
        $x_1_2 = "sms.php?id=" ascii //weight: 1
        $x_1_3 = "SenderService" ascii //weight: 1
        $x_1_4 = "/api/sms-test/install.php" ascii //weight: 1
        $x_1_5 = "SmsTester" ascii //weight: 1
        $x_1_6 = "getIncomingMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_T_2147835422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.T"
        threat_id = "2147835422"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "imgtxtxtxtxtxtxtgi" ascii //weight: 1
        $x_1_2 = "gmailforgtpass" ascii //weight: 1
        $x_1_3 = "deutschlandc64" ascii //weight: 1
        $x_1_4 = "foregroundify" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_G_2147843823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.G"
        threat_id = "2147843823"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vip/h5?plat=android" ascii //weight: 2
        $x_2_2 = "webandroid_isfirst_encome" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_H_2147845255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.H"
        threat_id = "2147845255"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "webandroid_isfirst_encome" ascii //weight: 2
        $x_2_2 = "WRITE_AND_READ_EXTERNAL_CODE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_I_2147846313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.I"
        threat_id = "2147846313"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sendDuphong" ascii //weight: 2
        $x_2_2 = "/save-phone-logs" ascii //weight: 2
        $x_2_3 = "urlAoc" ascii //weight: 2
        $x_2_4 = "/api/keywords-info" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_Q_2147847229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.Q!MTB"
        threat_id = "2147847229"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "speed_hacksms" ascii //weight: 1
        $x_1_2 = "_getAllContacts" ascii //weight: 1
        $x_1_3 = "ArabWareSMS" ascii //weight: 1
        $x_1_4 = "com/IVAR/SPEED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_P_2147849352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.P!MTB"
        threat_id = "2147849352"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/vnifood.com" ascii //weight: 1
        $x_1_2 = "fbok/subth/MainActivity" ascii //weight: 1
        $x_1_3 = "huynqassss" ascii //weight: 1
        $x_1_4 = "another_girl_in_the_wall_fb" ascii //weight: 1
        $x_1_5 = "sensms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_R_2147908236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.R!MTB"
        threat_id = "2147908236"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttps://apkafe.com/product/minecraft/" ascii //weight: 1
        $x_1_2 = "com/report/myap" ascii //weight: 1
        $x_1_3 = "RomiClient" ascii //weight: 1
        $x_1_4 = "/minecraft-romani-gg-update.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_J_2147908381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.J"
        threat_id = "2147908381"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "getKWfromServer" ascii //weight: 2
        $x_2_2 = "actionLoadAoc" ascii //weight: 2
        $x_2_3 = "sendKwDefault" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_Y_2147913369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.Y"
        threat_id = "2147913369"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sysncPermission" ascii //weight: 2
        $x_2_2 = "getSmsDataUpload" ascii //weight: 2
        $x_2_3 = "webapp/saveAddressBook" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_WR_2147919237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.WR"
        threat_id = "2147919237"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ll9NGFAZV1pAVxsIEw4FQmA=" ascii //weight: 1
        $x_1_2 = "LkVUWlRLY1JBQQ8TDhg=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_V_2147921686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.V!MTB"
        threat_id = "2147921686"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Telegram/ViP/TelegramActivity" ascii //weight: 1
        $x_1_2 = "_IConsPohenRAT" ascii //weight: 1
        $x_1_3 = "BOT_TOKEN" ascii //weight: 1
        $x_1_4 = "Block_Uesarname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_Z_2147923397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.Z"
        threat_id = "2147923397"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "getSmsDataUpload" ascii //weight: 2
        $x_2_2 = "webapp/saveSms" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeApp_BY_2147926434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeApp.BY"
        threat_id = "2147926434"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "104.233.167.116/prod-api/" ascii //weight: 2
        $x_2_2 = "getSmsDataUpload" ascii //weight: 2
        $x_2_3 = "sysncPermission" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

