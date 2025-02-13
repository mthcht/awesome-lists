rule TrojanSpy_AndroidOS_Faketoken_A_2147744253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Faketoken.A!MTB"
        threat_id = "2147744253"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Faketoken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ServMy Cmd.ChangeServer.COMMAND new server:" ascii //weight: 1
        $x_1_2 = "server TEXT, intercept TEXT, is_divice_admin INTEGER, text_info TEXT, scheck_del_msg INTEGER" ascii //weight: 1
        $x_1_3 = "SmsReceiver onReceive setSilentMode" ascii //weight: 1
        $x_1_4 = "getBlockSmsTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Faketoken_B_2147830610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Faketoken.B!MTB"
        threat_id = "2147830610"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Faketoken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/controller.php?mode=" ascii //weight: 1
        $x_1_2 = "isDeleteSms" ascii //weight: 1
        $x_1_3 = "scheck_del_msg" ascii //weight: 1
        $x_1_4 = "const_id_send_sms" ascii //weight: 1
        $x_1_5 = "registerBot" ascii //weight: 1
        $x_1_6 = "upServerSmsList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Faketoken_C_2147833986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Faketoken.C!MTB"
        threat_id = "2147833986"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Faketoken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "app/seven/MainActivity" ascii //weight: 1
        $x_1_2 = "textToCommand" ascii //weight: 1
        $x_1_3 = "getImsi" ascii //weight: 1
        $x_1_4 = "webapi.openUrl" ascii //weight: 1
        $x_1_5 = "sendTextMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Faketoken_D_2147834084_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Faketoken.D!MTB"
        threat_id = "2147834084"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Faketoken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 30 11 00 13 03 19 00 6e 20 ?? ?? 32 00 0a 03 8d 33 d8 03 03 61 8d 33 4f 03 01 00 d8 00 00 01 28 ef 22 00 59 00 70 20 ?? ?? 10 00 11 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/service.php" ascii //weight: 1
        $x_1_3 = "content://sms/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Faketoken_E_2147838251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Faketoken.E!MTB"
        threat_id = "2147838251"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Faketoken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Lcom/android/calculator" ascii //weight: 5
        $x_5_2 = "Lcom/azianames/foroneyhar" ascii //weight: 5
        $x_1_3 = "isAdminActive" ascii //weight: 1
        $x_1_4 = "setComponentEnabledSetting" ascii //weight: 1
        $x_1_5 = "sendTextMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

