rule Trojan_AndroidOS_FakeInstSms_A_2147652259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.A"
        threat_id = "2147652259"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getStringFromRawFile" ascii //weight: 1
        $x_1_2 = "tecsendtext" ascii //weight: 1
        $x_1_3 = "currentcountry" ascii //weight: 1
        $x_1_4 = "animationrow" ascii //weight: 1
        $x_1_5 = "nottreb" ascii //weight: 1
        $x_1_6 = "tecrool" ascii //weight: 1
        $x_1_7 = "SMS_DELIVERED" ascii //weight: 1
        $x_1_8 = "!!!Start Service!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_B_2147653459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.B"
        threat_id = "2147653459"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chank tEXt not found in png" ascii //weight: 1
        $x_1_2 = "termate/RuleActivity" ascii //weight: 1
        $x_1_3 = "reg_host" ascii //weight: 1
        $x_1_4 = "Error sending sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_B_2147653459_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.B"
        threat_id = "2147653459"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e1 0d 0a 10 49 0e 13 11 b7 ed 8e dd 50 0d 13 11 28 f2 0d 0d 28 e8 49 0d 13 11 b7 ad 8e dd 50 0d 13 11 28 e9 e1 0d 09 10 49 0e 13 11 b7 ed 8e dd 50 0d 13 11 28 e0 49 0d 13 11 b7 9d 8e dd 50 0d 13 11 28 d9 e1 0d 08 10 49 0e 13 11 b7 ed 8e dd 50 0d 13 11 28 d0}  //weight: 1, accuracy: High
        $x_1_2 = "Lcom/androids/update/Rec;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_C_2147678422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.C"
        threat_id = "2147678422"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutorunBroadcastReceiver" ascii //weight: 1
        $x_1_2 = {2f 63 6f 6e 6e 65 63 74 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 74 61 74 20 6d 61 6e 6e 75 61 6c 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 6d 73 52 65 63 69 76 65 72 2e 6a 61 76 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_C_2147678422_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.C"
        threat_id = "2147678422"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BinarySMSReceiver.java" ascii //weight: 1
        $x_1_2 = "Lcom/soft/android/appinstaller/services/SMSSenderService" ascii //weight: 1
        $x_1_3 = "Sorting SMS..." ascii //weight: 1
        $x_1_4 = "dcSmsCount" ascii //weight: 1
        $x_1_5 = "fillSmsInfo()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_D_2147684313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.D"
        threat_id = "2147684313"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 01 a7 01 70 10 25 08 01 00 22 02 a4 01 22 03 7f 01 1a 04 11 05 70 20 c6 07 43 00 54 a4 72 02 6e 10 a8 06 04 00 0c 04 6e 20 cb 07 43 00 0c 03 1a 04 77 00 6e 20 cb 07 43 00 0c 03 12 04 46 04 0b 04 6e 20 cb 07 43 00 0c 03 1a 04 82}  //weight: 1, accuracy: High
        $x_1_2 = {0c 03 1a 04 7d 00 6e 20 cb 07 43 00 0c 03 6e 20 cb 07 23 00 0c 02 1a 03 79 00 6e 20 cb 07 32 00 0c 02 6e 20 cb 07 12 00 0c 01 1a 02 75 00}  //weight: 1, accuracy: High
        $x_1_3 = "http://apps.sexurus.com/php/index.php/?tag=usersave&username=" ascii //weight: 1
        $x_1_4 = "&numero=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_E_2147757954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.E"
        threat_id = "2147757954"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Jk7H.PwcD.SLYfoMdG" ascii //weight: 1
        $x_1_2 = "/res/raw/data.db" ascii //weight: 1
        $x_1_3 = "loadSmsCountMethod" ascii //weight: 1
        $x_1_4 = {73 65 6e 74 53 6d 73 ?? ?? 73 65 6e 74 53 6d 73 43 6f 75 6e 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_F_2147758167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.F"
        threat_id = "2147758167"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SENT_SMS_COUNT_KEY" ascii //weight: 1
        $x_1_2 = "INSTALLLED_TEXT_TAG" ascii //weight: 1
        $x_1_3 = {42 45 4c 4c 4f 52 55 53 53 5f 49 44 [0-21] 42 57 43 5f 49 44}  //weight: 1, accuracy: Low
        $x_1_4 = "ns5ru_m" ascii //weight: 1
        $x_1_5 = "act_schemes" ascii //weight: 1
        $x_1_6 = "cntryTag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_G_2147759317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.G"
        threat_id = "2147759317"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jp.selerino.bredno" ascii //weight: 1
        $x_1_2 = "parsnewdataandsend" ascii //weight: 1
        $x_1_3 = "setroolsdisplay" ascii //weight: 1
        $x_1_4 = "prvl.txt" ascii //weight: 1
        $x_1_5 = "sendSMSkahi" ascii //weight: 1
        $x_1_6 = "ESLIABONENTTUPIT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_H_2147787702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.H"
        threat_id = "2147787702"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*CNT_NAME*" ascii //weight: 1
        $x_1_2 = "getURLHasToBeActed" ascii //weight: 1
        $x_1_3 = "BELORUS_ID" ascii //weight: 1
        $x_1_4 = "KEY_NOTIFICATION_NUMBER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_I_2147787703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.I"
        threat_id = "2147787703"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LJk7H/PwcD/SLYfoMdG" ascii //weight: 1
        $x_1_2 = "loadSmsCount" ascii //weight: 1
        $x_1_3 = "Lorg/MobileDb/MobileDatabase" ascii //weight: 1
        $x_1_4 = "licenseWithOneButton" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_J_2147787844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.J"
        threat_id = "2147787844"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/OffertActivity;" ascii //weight: 1
        $x_1_2 = "apps_dir_wasnt_created" ascii //weight: 1
        $x_1_3 = "initDataFromConfigs" ascii //weight: 1
        $x_1_4 = "installedContentTextView" ascii //weight: 1
        $x_1_5 = "decreaseNotificationNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_K_2147787845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.K"
        threat_id = "2147787845"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setroolsdisplay" ascii //weight: 1
        $x_1_2 = "showmessinternet" ascii //weight: 1
        $x_1_3 = "/ProinActivity;" ascii //weight: 1
        $x_1_4 = "configpach" ascii //weight: 1
        $x_1_5 = "rools.txt" ascii //weight: 1
        $x_1_6 = "ESLIABONENTTUPIT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_CA_2147787846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.CA"
        threat_id = "2147787846"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/soft/android/appinstaller/sms/BinarySMSReceiver" ascii //weight: 1
        $x_1_2 = "getDcSmsCount" ascii //weight: 1
        $x_1_3 = "UnconfirmableSMSSenderEngineImpl" ascii //weight: 1
        $x_1_4 = "expectedMoneyRest" ascii //weight: 1
        $x_1_5 = "SmsInfo() C-tor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_L_2147787847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.L"
        threat_id = "2147787847"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Content-Disposition: form-data; name=\"manufacturer\"" ascii //weight: 1
        $x_1_2 = "KStartContent" ascii //weight: 1
        $x_1_3 = "Lru/alpha/AlphaApiResult" ascii //weight: 1
        $x_1_4 = "Lru/alpha/AlphaReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_CB_2147787848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.CB"
        threat_id = "2147787848"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/soft/android/appinstaller/RulesActivity" ascii //weight: 1
        $x_1_2 = "parseConfigLineMCCMNC" ascii //weight: 1
        $x_1_3 = "getSmsSentCount" ascii //weight: 1
        $x_1_4 = "getRulesTexts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_IA_2147787849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.IA"
        threat_id = "2147787849"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BeqtICiSekdj" ascii //weight: 1
        $x_1_2 = "Jk7H.PwcD.SLYfoMdG" ascii //weight: 1
        $x_1_3 = "/res/raw/data.db" ascii //weight: 1
        $x_1_4 = "xjyQnhjsxjRjymti" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_JA_2147788167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.JA"
        threat_id = "2147788167"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SENDED_SMS_COUNTER_KEY" ascii //weight: 1
        $x_1_2 = "PAYED_KEY" ascii //weight: 1
        $x_1_3 = "SMS_DATA_KEY" ascii //weight: 1
        $x_1_4 = "com.software.android.install.permission.C2D_MESSAGE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_JB_2147788168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.JB"
        threat_id = "2147788168"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/EvvuhjQsjylyjO;" ascii //weight: 1
        $x_1_2 = "/Dejyvysqjeh;" ascii //weight: 1
        $x_1_3 = "/Qsjeh;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_JC_2147794388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.JC"
        threat_id = "2147794388"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!!!device_id=" ascii //weight: 1
        $x_1_2 = "Lcom/extend/battery/" ascii //weight: 1
        $x_1_3 = "PREF_LAST_INSTALLED_VERSION" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_M_2147794783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.M"
        threat_id = "2147794783"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pIW_WUJ_FXEDU_DKpRUH" ascii //weight: 1
        $x_1_2 = "iqluVyBudqCu" ascii //weight: 1
        $x_1_3 = "/FxeduDkCruhTyqBew;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeInstSms_A_2147830923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeInstSms.A!MTB"
        threat_id = "2147830923"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeInstSms"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 40 36 30 46 05 f0 39 fb a5 63 44 34 20 46 05 f0 44 fb 30 46 05 f0 39 fb 3c e0 25 46 40 35 28 46 05 f0 2b fb 20 6a 00 28 01 d0 05 f0 3e fb e0 6f 20 62 00 28 11 d0 e1 69 22 46 60 32 6b 46 1a 60 02 22 00 23 05 f0 39 fb 07 e0 25 46 40 35 28 46 05 f0 13 fb 80 20 20 58 60 62 44 34 20 46 05 f0 1c fb 28 46 05 f0 11 fb 14 e0 44 34 20 46 05 f0 14 fb 0f e0 20 69 e1 68 09 6a 05 f0 26 fb 20 69 03 a9 05 f0 2a fb 20 69 02 a9 05 f0 2e fb 01 e0 01 20}  //weight: 1, accuracy: High
        $x_1_2 = "Activating DexLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

