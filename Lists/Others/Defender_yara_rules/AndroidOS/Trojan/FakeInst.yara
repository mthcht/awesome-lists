rule Trojan_AndroidOS_FakeInst_B_2147778618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.B!MTB"
        threat_id = "2147778618"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AutoRunner.jar" ascii //weight: 2
        $x_1_2 = "copyAssetApk2Storage" ascii //weight: 1
        $x_1_3 = "silentInstall" ascii //weight: 1
        $x_1_4 = "pm install -r" ascii //weight: 1
        $x_1_5 = "hasRootPerssion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_FakeInst_AS_2147783123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.AS!MTB"
        threat_id = "2147783123"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "startSMSMonitoring" ascii //weight: 1
        $x_1_2 = "sms_composer" ascii //weight: 1
        $x_1_3 = "SIM_STATE_PIN_REQUIRED" ascii //weight: 1
        $x_1_4 = "send_installed" ascii //weight: 1
        $x_1_5 = "SmartCleaner.apk" ascii //weight: 1
        $x_1_6 = "mosent.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_C_2147783790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.C!MTB"
        threat_id = "2147783790"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendAfterStart" ascii //weight: 1
        $x_1_2 = "raw/sms.xml" ascii //weight: 1
        $x_1_3 = "catchSms" ascii //weight: 1
        $x_1_4 = "Lcom/load/wap/SmsReciver" ascii //weight: 1
        $x_1_5 = "removeAllSmsFilters" ascii //weight: 1
        $x_1_6 = "sendContactList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_D_2147788226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.D!MTB"
        threat_id = "2147788226"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MySMSMonitor" ascii //weight: 1
        $x_1_2 = "SMS is deleted" ascii //weight: 1
        $x_1_3 = "inbox is added" ascii //weight: 1
        $x_1_4 = "iMTCPay" ascii //weight: 1
        $x_1_5 = "Lcom/androidinstall/client/Licenze" ascii //weight: 1
        $x_1_6 = "sentbox is added" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_F_2147788976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.F"
        threat_id = "2147788976"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wujXqdtBuhJxhuqt" ascii //weight: 1
        $x_1_2 = "xqdtBupuiiqwu" ascii //weight: 1
        $x_1_3 = "CoesqBOjysiNuO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_E_2147792921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.E!MTB"
        threat_id = "2147792921"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Opera Mini NEW_EW_EW" ascii //weight: 1
        $x_1_2 = "sms_num" ascii //weight: 1
        $x_1_3 = "stimulpremium.com/rules.php" ascii //weight: 1
        $x_1_4 = "MAX_SMS_MESSAGE" ascii //weight: 1
        $x_1_5 = "mobile-premium.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_G_2147794707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.G"
        threat_id = "2147794707"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "seC/qdtheyt/Cqyd/ICiHusuyluh;" ascii //weight: 1
        $x_1_2 = "/RqiuQkjxudysqjyedXjjfSByudj;" ascii //weight: 1
        $x_1_3 = "rheqtsqijHusuyluhmhyju" ascii //weight: 1
        $x_1_4 = "JQDSQsjylyjO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_FakeInst_H_2147794708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.H"
        threat_id = "2147794708"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "seC/CCi/rw/jhqdiqsjyed/FhylyBuwutICiHusuyluh;" ascii //weight: 1
        $x_1_2 = "/sxydqCeryBu10086/kjyBi/oufxeduIkffehj;" ascii //weight: 1
        $x_1_3 = "VqnuoqdksxuhQsjylyjO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_GA_2147808190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.GA"
        threat_id = "2147808190"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "seC/Beqt/mqf/ICiHusyluh;" ascii //weight: 1
        $x_1_2 = "QBqhCHusuyluh;" ascii //weight: 1
        $x_1_3 = "pqydQffBysqjyed;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_GB_2147808191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.GB"
        threat_id = "2147808191"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "seC/iuskhyjO/iuhlysu/husuyluh/HureejHusuyluh;" ascii //weight: 1
        $x_1_2 = "UjwxnxyjshjRfsfljw.ofaf" ascii //weight: 1
        $x_1_3 = "Sedijqdji;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_GC_2147808192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.GC"
        threat_id = "2147808192"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LseC/CersBysn/qdtheyt/KCudwVuutrqsn;" ascii //weight: 1
        $x_1_2 = "RfnsFhynanyd.ofaf" ascii //weight: 1
        $x_1_3 = "Lsd/seC/wm/BylumqBBfqfuh_Osj/bSJByluMqBBfqfuh;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_I_2147810562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.I"
        threat_id = "2147810562"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 00 0c 07 12 08 71 20 ?? ?? 87 00 0c 03 22 04 ?? ?? 70 20 ?? ?? 34 00 22 06 ?? ?? 70 10 ?? ?? 06 00 12 00 6e 10 ?? ?? 04 00 0a 07 35 70 18 00 6e 20 ?? ?? 04 00 0a 07 6e 10 ?? ?? 01 00 0a 08 94 08 00 08 6e 20 ?? ?? 81 00 0a 08 b7 87 8e 77 6e 20 ?? ?? 76 00 d8 00 00 01 28 e5 6e 10 ?? ?? 06 00 0c 02 11 02}  //weight: 2, accuracy: Low
        $x_2_2 = {05 00 0c 07 12 08 71 20 ?? ?? 87 00 0c 03 22 04 ?? ?? 70 20 ?? ?? 34 00 22 06 ?? ?? 70 10 ?? ?? 06 00 12 00 71 10 ?? ?? 04 00 0a 07 35 70 18 00 71 20 ?? ?? 04 00 0a 07 71 10 ?? ?? 01 00 0a 08 94 08 00 08 71 20 ?? ?? 81 00 0a 08 b7 87 8e 77 71 20 ?? ?? 76 00 d8 00 00 01 28 e5 71 10 ?? ?? 06 00 0c 02 11 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_AndroidOS_FakeInst_J_2147810563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.J"
        threat_id = "2147810563"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 00 0a 05 23 52 28 00 1a 01 ?? ?? 22 04 ?? ?? 22 05 ?? ?? 70 10 ?? ?? 05 00 6e 10 ?? ?? 07 00 0c 06 6e 20 ?? ?? 65 00 0c 05 62 06 ?? ?? 6e 20 ?? ?? 65 00 0c 05 6e 20 ?? ?? 15 00 0c 05 22 06 ?? ?? 70 10 ?? ?? 06 00 6e 10 ?? ?? 06 00 0a 06 6e 20 ?? ?? 65 00 0c 05 1a 06 ?? ?? 6e 20 ?? ?? 65 00 0c 05 6e 10 ?? ?? 05 00 0c 05 70 20 ?? ?? 54 00 6e 10 ?? ?? 04 00 6e 20 ?? ?? 28 00 1a 05 ?? ?? 6e 10 ?? ?? 05 00 0c 05 71 20 ?? ?? 52 00 0c 02 6e 10 ?? ?? 08 00 07 20 22 03 ?? ?? 70 20 ?? ?? 43 00 70 30 ?? ?? 37 00 11 04}  //weight: 1, accuracy: Low
        $x_1_2 = "ra/Appl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_F_2147817118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.F!MTB"
        threat_id = "2147817118"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getMessageListByLoc" ascii //weight: 1
        $x_1_2 = "SaveMsgToFile" ascii //weight: 1
        $x_1_3 = "getMessageList" ascii //weight: 1
        $x_1_4 = "cancelCurrNotif" ascii //weight: 1
        $x_1_5 = "goPliPayActivityByUrl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_K_2147818011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.K!MTB"
        threat_id = "2147818011"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "joinmobil.ru" ascii //weight: 1
        $x_1_2 = "/stats/adv.php qstszd=" ascii //weight: 1
        $x_1_3 = "checkcomand" ascii //weight: 1
        $x_1_4 = "android.telephony.gsm.SmsManager" ascii //weight: 1
        $x_1_5 = "reulturl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_K_2147818011_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.K!MTB"
        threat_id = "2147818011"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "killProcess" ascii //weight: 1
        $x_2_2 = {12 04 23 71 ?? 02 28 02 b0 26 8d 62 4f 02 01 04 d8 05 05 01 d8 04 04 01 33 74 [0-5] 12 02 70 30 [0-5] 10 02 6e 10 [0-5] 00 00 0c 00 11 00 48 02 03 05}  //weight: 2, accuracy: Low
        $x_2_3 = {12 f4 da 08 08 04 d8 08 08 01 62 05 c0 05 22 00 01 02 23 81 5d 02 d8 08 08 ff [0-5] 91 02 06 02 d8 06 02 fe d8 04 04 01 8d 62 4f 02 01 04 33 84 [0-5] 12 02 70 30 [0-5] 10 02 11 00 d8 07 07 01 48 02 05 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_FakeInst_L_2147825028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.L!MTB"
        threat_id = "2147825028"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6d 2f 63 61 69 61 70 70 2f 73 6b 79 70 65 [0-32] 4d 61 69 6e 41 63 74 69 76 69 74 79}  //weight: 1, accuracy: Low
        $x_1_2 = {63 6f 6d 2f 6d 6f 62 69 61 64 73 2f 69 6e 73 74 61 6c 6c 65 72 2f [0-32] 4d 61 69 6e 41 63 74 69 76 69 74 79}  //weight: 1, accuracy: Low
        $x_1_3 = "http://a.taigamemobilehay.net/mo-kh.php?app=" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f ?? 2e 74 61 69 67 61 6d 65 6d 6f 62 69 6c 65 68 61 79 2e 6e 65 74 [0-16] 2f 6d 6f 2d 6b 68 2e 6a 73 70 3f 61 70 70 3d}  //weight: 1, accuracy: Low
        $x_1_5 = "vn/mwork/android/mhubmanager/MHubManager" ascii //weight: 1
        $x_1_6 = "URL_INSTALL" ascii //weight: 1
        $x_1_7 = "killProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_FakeInst_M_2147826774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.M!MTB"
        threat_id = "2147826774"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 24 14 00 48 06 09 04 48 07 08 05 b7 76 8d 66 4f 06 03 04 d8 05 05 01 d8 06 01 ff 37 65 03 00 01 05 d8 04 04 01 28 ed}  //weight: 1, accuracy: High
        $x_1_2 = "com/slacken/work/mischie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_G_2147830697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.G!MTB"
        threat_id = "2147830697"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autopay_session" ascii //weight: 1
        $x_1_2 = "sms_extra" ascii //weight: 1
        $x_1_3 = "data.res" ascii //weight: 1
        $x_1_4 = "agreement_text" ascii //weight: 1
        $x_1_5 = "rates.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_N_2147831785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.N!MTB"
        threat_id = "2147831785"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "o5sms.com/api/trace/" ascii //weight: 1
        $x_1_2 = "agree.txt" ascii //weight: 1
        $x_1_3 = "rates.php" ascii //weight: 1
        $x_1_4 = "data.res" ascii //weight: 1
        $x_1_5 = "sendTextMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_O_2147832997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.O!MTB"
        threat_id = "2147832997"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getMobielNo" ascii //weight: 1
        $x_1_2 = "HideMessage" ascii //weight: 1
        $x_1_3 = "ReverseOnBoard" ascii //weight: 1
        $x_1_4 = "androidhitgames.ru/log/msg" ascii //weight: 1
        $x_1_5 = "WritePhonePref" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_FakeInst_H_2147834451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.H!MTB"
        threat_id = "2147834451"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "org/unfin/dev" ascii //weight: 1
        $x_1_2 = "config.txt" ascii //weight: 1
        $x_1_3 = "smsSendTime" ascii //weight: 1
        $x_1_4 = "getTegContent" ascii //weight: 1
        $x_1_5 = "R%hjk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_P_2147841798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.P!MTB"
        threat_id = "2147841798"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xBotLocker" ascii //weight: 1
        $x_1_2 = "issmstimer" ascii //weight: 1
        $x_1_3 = "com/malice/updater" ascii //weight: 1
        $x_1_4 = "xBotService" ascii //weight: 1
        $x_1_5 = "/interface.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_Q_2147841985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.Q!MTB"
        threat_id = "2147841985"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sksmskeyword" ascii //weight: 1
        $x_1_2 = "script.starpass.fr/script.php?idd=53153&amp;datas=" ascii //weight: 1
        $x_1_3 = "SmsReceiver" ascii //weight: 1
        $x_1_4 = "deleteSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_R_2147842591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.R!MTB"
        threat_id = "2147842591"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sms_thread_version1" ascii //weight: 1
        $x_1_2 = "check_Alive" ascii //weight: 1
        $x_1_3 = "smsreceiveandmask" ascii //weight: 1
        $x_1_4 = "com/xmobileapp/Snake_lv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_S_2147846257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.S!MTB"
        threat_id = "2147846257"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReadAllTextFromStream" ascii //weight: 1
        $x_1_2 = "MyPhoneClass" ascii //weight: 1
        $x_1_3 = "getWhorePhone" ascii //weight: 1
        $x_1_4 = "com/loadfon/filer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_S_2147846257_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.S!MTB"
        threat_id = "2147846257"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vnitourist.com" ascii //weight: 1
        $x_1_2 = "apichecksubs.modobomco.com/check-subs?country=romania" ascii //weight: 1
        $x_1_3 = "ConfirtinReceiver" ascii //weight: 1
        $x_1_4 = "FLAG_CONFIRM_KW1" ascii //weight: 1
        $x_1_5 = "NhanReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_K_2147848664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.K"
        threat_id = "2147848664"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FLAG_CONFIRM_KW1" ascii //weight: 2
        $x_2_2 = "sub/ConfirmSmsReceiver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_T_2147890541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.T!MTB"
        threat_id = "2147890541"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConfirtinReceiver" ascii //weight: 1
        $x_1_2 = "FLAG_CONFIRM_KW1" ascii //weight: 1
        $x_1_3 = "vnitourist.com" ascii //weight: 1
        $x_1_4 = "actionAOC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_U_2147895673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.U!MTB"
        threat_id = "2147895673"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pdp_text_mf_end" ascii //weight: 1
        $x_1_2 = "isMTSSubscription" ascii //weight: 1
        $x_1_3 = "isMFSubscription" ascii //weight: 1
        $x_1_4 = "sendMsg" ascii //weight: 1
        $x_1_5 = "GOT_MESSAGE_RESP_KEY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_V_2147895674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.V!MTB"
        threat_id = "2147895674"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setroolsdisplay" ascii //weight: 1
        $x_1_2 = "rools.txt" ascii //weight: 1
        $x_1_3 = "com/uniplugin/sender" ascii //weight: 1
        $x_1_4 = "/stats/adv.php" ascii //weight: 1
        $x_1_5 = "sendSMSki" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_J_2147902750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.J!MTB"
        threat_id = "2147902750"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_commonautosend" ascii //weight: 1
        $x_1_2 = "belorus_linked_text_2" ascii //weight: 1
        $x_1_3 = "BELLORUSS_ID" ascii //weight: 1
        $x_1_4 = "FIRST_MTS_SEND_10" ascii //weight: 1
        $x_1_5 = "com.googleapps.ru" ascii //weight: 1
        $x_1_6 = "SENT_SMS_COUNT_KEY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_W_2147902751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.W!MTB"
        threat_id = "2147902751"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SENT_SMS_NUMBER_KEY" ascii //weight: 1
        $x_1_2 = "FIRST_SEND_10" ascii //weight: 1
        $x_1_3 = "BELLORUSS_ID" ascii //weight: 1
        $x_1_4 = "com.googleapi.cover" ascii //weight: 1
        $x_1_5 = "isMTSRF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_FakeInst_X_2147908991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.X!MTB"
        threat_id = "2147908991"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "topfiless.com/rates.php" ascii //weight: 1
        $x_1_2 = "com/send/loader" ascii //weight: 1
        $x_1_3 = "agreement.txt" ascii //weight: 1
        $x_1_4 = "getNetworkCountryIso" ascii //weight: 1
        $x_1_5 = "ru_mega" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInst_S_2147919945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInst.S"
        threat_id = "2147919945"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "samagonteam" ascii //weight: 2
        $x_2_2 = "gruppaduna" ascii //weight: 2
        $x_2_3 = "trirubaha" ascii //weight: 2
        $x_2_4 = "sendSMS777" ascii //weight: 2
        $x_2_5 = "getlinkconfig345" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

