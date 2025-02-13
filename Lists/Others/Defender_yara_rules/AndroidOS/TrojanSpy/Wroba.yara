rule TrojanSpy_AndroidOS_Wroba_B_2147767764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.B!MTB"
        threat_id = "2147767764"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|*callEntity*|" ascii //weight: 1
        $x_1_2 = "|*telEntityArrayList*|" ascii //weight: 1
        $x_1_3 = "/dircall" ascii //weight: 1
        $x_1_4 = "Network_SerMod" ascii //weight: 1
        $x_1_5 = "persist.txt" ascii //weight: 1
        $x_1_6 = "contacts.dat" ascii //weight: 1
        $x_1_7 = ".uploadNumber =" ascii //weight: 1
        $x_1_8 = "update.CallLog:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_Wroba_C_2147768133_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.C!MTB"
        threat_id = "2147768133"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DeAdminReciver" ascii //weight: 1
        $x_1_2 = "MISSION_POPINFO_BYPASS" ascii //weight: 1
        $x_1_3 = "com.xxx.GS" ascii //weight: 1
        $x_1_4 = "kakaotalk.synservice.URL" ascii //weight: 1
        $x_1_5 = "com/ll/FNA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Wroba_D_2147768528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.D!MTB"
        threat_id = "2147768528"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "onCreditCardTypeChanged" ascii //weight: 1
        $x_1_2 = "/user_info_uploader" ascii //weight: 1
        $x_1_3 = "/.update2/" ascii //weight: 1
        $x_1_4 = "sms_kw_sent" ascii //weight: 1
        $x_1_5 = "is_call_rec_enable" ascii //weight: 1
        $x_1_6 = "get_gallery" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Wroba_M_2147786465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.M!MTB"
        threat_id = "2147786465"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 00 04 23 44 30 00 ?? ?? ?? ?? ?? ?? 0a 05 12 f6 ?? ?? ?? ?? 70 40 ?? 00 98 42 0e 00 12 06 35 56 0b 00 48 07 04 06 b7 17 8d 77 4f 07 04 06 d8 06 06 01 28 f6 ?? ?? ?? ?? ?? ?? 28 e6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Wroba_E_2147810964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.E!MTB"
        threat_id = "2147810964"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B23hb27" ascii //weight: 1
        $x_1_2 = "/servlet/UploadVoice" ascii //weight: 1
        $x_1_3 = "/servlet/ContactsUpload" ascii //weight: 1
        $x_1_4 = "getBanksInfo" ascii //weight: 1
        $x_1_5 = "45006" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Wroba_E_2147810964_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.E!MTB"
        threat_id = "2147810964"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sms Lock" ascii //weight: 1
        $x_1_2 = "stop forward" ascii //weight: 1
        $x_1_3 = "_Otp_Psw" ascii //weight: 1
        $x_1_4 = "_Card_Psw" ascii //weight: 1
        $x_1_5 = "&sendoutOrIn=" ascii //weight: 1
        $x_1_6 = "execute command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Wroba_F_2147815397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.F!MTB"
        threat_id = "2147815397"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uploadLocationToServer" ascii //weight: 1
        $x_1_2 = "api/addUserInfo" ascii //weight: 1
        $x_1_3 = "api/getAllIncoming" ascii //weight: 1
        $x_1_4 = "UPloadFileService" ascii //weight: 1
        $x_1_5 = "sendMsgForPhoneStatus" ascii //weight: 1
        $x_1_6 = "SocketClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Wroba_G_2147816080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.G!MTB"
        threat_id = "2147816080"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "L3NhdmVkaW5zdGFuY2VzdGF0ZS5sb2Z0ZXIuY29t" ascii //weight: 1
        $x_1_2 = "PhoneManager/services/BankWebService?wsdl" ascii //weight: 1
        $x_1_3 = "com/cashweb/android/wooribank" ascii //weight: 1
        $x_1_4 = "initWebServiceUrl" ascii //weight: 1
        $x_1_5 = "getNewestHost" ascii //weight: 1
        $x_1_6 = "download_any" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Wroba_H_2147828946_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.H!MTB"
        threat_id = "2147828946"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tryHideIcon" ascii //weight: 1
        $x_1_2 = "DeAdminReciver" ascii //weight: 1
        $x_1_3 = "getBankBgByShort" ascii //weight: 1
        $x_1_4 = "MISSION_HIJACK_BANK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Wroba_J_2147831402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.J!MTB"
        threat_id = "2147831402"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DeAdminReciver" ascii //weight: 1
        $x_1_2 = "com.kakaotalk.synservice.TIK" ascii //weight: 1
        $x_1_3 = "killBackgroundProcesses" ascii //weight: 1
        $x_1_4 = "createFromPdu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Wroba_I_2147837783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.I!MTB"
        threat_id = "2147837783"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BK_CALL_LIST" ascii //weight: 3
        $x_1_2 = "NOBANKURL" ascii //weight: 1
        $x_1_3 = "/servlet/ContactsUpload" ascii //weight: 1
        $x_1_4 = "AutBankInter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Wroba_K_2147840484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Wroba.K!MTB"
        threat_id = "2147840484"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sms Lock" ascii //weight: 1
        $x_1_2 = "notify upload result" ascii //weight: 1
        $x_1_3 = "db4SMS" ascii //weight: 1
        $x_1_4 = "webcash.wooribank" ascii //weight: 1
        $x_1_5 = "add.php result" ascii //weight: 1
        $x_1_6 = "upload_sms start" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

