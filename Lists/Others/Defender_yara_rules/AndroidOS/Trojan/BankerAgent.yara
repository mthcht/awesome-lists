rule Trojan_AndroidOS_BankerAgent_A_2147794678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.A"
        threat_id = "2147794678"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KEY_UPLOAD_1" ascii //weight: 2
        $x_2_2 = "KEY_TELECOMS_NAME" ascii //weight: 2
        $x_2_3 = "5H6+Pjq70O4usQ67KuPwww==" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_B_2147836257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.B"
        threat_id = "2147836257"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "foregttss" ascii //weight: 2
        $x_2_2 = "creyENVIAsMS" ascii //weight: 2
        $x_2_3 = "contadorSendsSM" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_KJ_2147897618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.KJ"
        threat_id = "2147897618"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/b.kunlun666.xyz/#/" ascii //weight: 2
        $x_2_2 = "is_locked_device" ascii //weight: 2
        $x_2_3 = "is_success_get_permissions" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_P_2147897912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.P"
        threat_id = "2147897912"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "adpter_smsread" ascii //weight: 2
        $x_2_2 = "Divice_Block" ascii //weight: 2
        $x_2_3 = "Card_ReUpload" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_Q_2147897913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.Q"
        threat_id = "2147897913"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bank12.php?m=Api&a=Sms&imsi=" ascii //weight: 2
        $x_2_2 = "zipNPKI" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_H_2147899120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.H"
        threat_id = "2147899120"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bank12.php?m=Api&a=Sms&imsi=" ascii //weight: 2
        $x_2_2 = "abc/EnActivity" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_Y_2147906778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.Y"
        threat_id = "2147906778"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ignore_battery_optimisations" ascii //weight: 2
        $x_2_2 = "PostDataNodeCard" ascii //weight: 2
        $x_2_3 = "RegisterReceiverInternet" ascii //weight: 2
        $x_2_4 = "PostDataNodeInstall" ascii //weight: 2
        $x_2_5 = "REWD_Select" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_L_2147907016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.L"
        threat_id = "2147907016"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "apinew/activecheck.php" ascii //weight: 2
        $x_2_2 = "smslistner/PackageRemovalReceiver" ascii //weight: 2
        $x_2_3 = "thankyouscreen/ThankyouScreen" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_J_2147908382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.J"
        threat_id = "2147908382"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/sms-reader/add" ascii //weight: 2
        $x_2_2 = "/site/number?site" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_T_2147912363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.T"
        threat_id = "2147912363"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "activeInjectAppPackage" ascii //weight: 2
        $x_2_2 = "isHiddenVNC" ascii //weight: 2
        $x_2_3 = "activeInjectLogId" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_M_2147912364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.M"
        threat_id = "2147912364"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sendSmstoerver" ascii //weight: 2
        $x_2_2 = "api/app/client_details" ascii //weight: 2
        $x_2_3 = "receiver/SmsRepository" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_AK_2147919636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.AK"
        threat_id = "2147919636"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/api/bingoplus_get_phone_number_status" ascii //weight: 2
        $x_2_2 = "bingoPlusPassword" ascii //weight: 2
        $x_4_3 = "zaebal/core/SmsMessageReceiver" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_BankerAgent_AG_2147920427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.AG"
        threat_id = "2147920427"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "v1.apijson.xyz/app-store?id=" ascii //weight: 2
        $x_2_2 = "Choosing subscription based SMSManager" ascii //weight: 2
        $x_2_3 = "Sms forward on but numbers empty?" ascii //weight: 2
        $x_2_4 = "Sms forward off or message contain empty?" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_AE_2147924226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.AE"
        threat_id = "2147924226"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "o1p2e3n4t5h6i7r8d9l0o1a2d3i4n5g6p7a8g9e0five" ascii //weight: 2
        $x_2_2 = "URL_ATMac" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_BX_2147940548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.BX"
        threat_id = "2147940548"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/example/omantelprize/ServiceRestarterBroadcastReceiver" ascii //weight: 2
        $x_2_2 = "New, better app experiance" ascii //weight: 2
        $x_2_3 = "omantelprize/OnboardingActivity" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_BankerAgent_BI_2147940549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankerAgent.BI"
        threat_id = "2147940549"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankerAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ChangeSmsDefaultAppActivity" ascii //weight: 2
        $x_2_2 = "FitnessAccessibilityService" ascii //weight: 2
        $x_2_3 = "UserPresentReceiverService" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

