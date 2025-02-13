rule TrojanSpy_AndroidOS_Bahamut_B_2147766833_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bahamut.B!MTB"
        threat_id = "2147766833"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bahamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 61 6c 6c 20 44 75 72 61 74 69 6f 6e 2d 2d 00 0e 20 2c 20 43 61 6c 6c 20 54 79 70 65 2d 2d 00 0f 20 2c 20 43 61 6c 6c 65 72 4e 61 6d 65 2d 2d 00}  //weight: 2, accuracy: High
        $x_1_2 = {1d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 3e 3e 0a 20 44 65 76 69 63 65 20 49 6e 66 6f 20 20 3a 20 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 3e 3e 0a 4d 65 73 73 61 67 65 73 20}  //weight: 1, accuracy: High
        $x_1_4 = "PhoneNumber --" ascii //weight: 1
        $x_1_5 = {4d 65 64 69 61 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 61 6c 6c 48 69 73 74 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 6c 6f 77 66 69 73 68 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Bahamut_C_2147788030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bahamut.C"
        threat_id = "2147788030"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bahamut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.example.jamaat" ascii //weight: 1
        $x_1_2 = "IntializeSocket" ascii //weight: 1
        $x_1_3 = "SaveCallLogstoDatabase" ascii //weight: 1
        $x_1_4 = "insertTaskAsynckContacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Bahamut_D_2147788031_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bahamut.D"
        threat_id = "2147788031"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bahamut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SmsAllBroadCast" ascii //weight: 2
        $x_2_2 = "K&M9B#)O/R\\=P%hA" ascii //weight: 2
        $x_1_3 = "com.greenflag.system" ascii //weight: 1
        $x_1_4 = "com.fors.apps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Bahamut_E_2147807293_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bahamut.E"
        threat_id = "2147807293"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bahamut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSG_TRIG_ALARM_HEARTBEAT" ascii //weight: 1
        $x_1_2 = "NetworkStatusService$" ascii //weight: 1
        $x_1_3 = "MSG_CONNECTIVITY" ascii //weight: 1
        $x_1_4 = "djdeeu$tuygln" ascii //weight: 1
        $x_1_5 = "water.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Bahamut_F_2147810564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bahamut.F"
        threat_id = "2147810564"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bahamut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lorga/mime/BootCompleteReceiver;" ascii //weight: 1
        $x_1_2 = "/ShellService;" ascii //weight: 1
        $x_1_3 = "titeperformance.com" ascii //weight: 1
        $x_1_4 = "com.at.coder.commandhandler.MessageHandler" ascii //weight: 1
        $x_1_5 = "update.jar" ascii //weight: 1
        $x_1_6 = "^update[a-zA-Z0-9_]*\\.jar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Bahamut_FA_2147810565_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bahamut.FA"
        threat_id = "2147810565"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bahamut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/at/coder/commandhandler/MessageHandler;" ascii //weight: 1
        $x_1_2 = "recoder_" ascii //weight: 1
        $x_1_3 = "com.at.coder.commandhandler" ascii //weight: 1
        $x_1_4 = "offhook1" ascii //weight: 1
        $x_1_5 = "msgfolder" ascii //weight: 1
        $x_1_6 = "{\"command\":\"%s\",\"path\":\"%s\",\"files\"" ascii //weight: 1
        $x_1_7 = "{\"name\":\"%s\",\"dirs\":\"%d\",\"files\":\"%d\",\"isfolder\":\"%d\",\"path\":\"%s\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_Bahamut_G_2147825118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bahamut.G"
        threat_id = "2147825118"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bahamut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$callLogDao" ascii //weight: 1
        $x_1_2 = "$smsDao" ascii //weight: 1
        $x_1_3 = "$viberDao" ascii //weight: 1
        $x_1_4 = "$imoDao" ascii //weight: 1
        $x_1_5 = "$protectedDao" ascii //weight: 1
        $x_1_6 = "$signalDao" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Bahamut_H_2147825119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bahamut.H"
        threat_id = "2147825119"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bahamut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getBASE_SOCKET_URL" ascii //weight: 1
        $x_1_2 = "_whatsappDao" ascii //weight: 1
        $x_1_3 = "getNonserverContacts" ascii //weight: 1
        $x_1_4 = "$telegraphDao" ascii //weight: 1
        $x_1_5 = "getCall_log_id" ascii //weight: 1
        $x_1_6 = "getFb_title_array" ascii //weight: 1
        $x_1_7 = "CallLogDao_Impl" ascii //weight: 1
        $x_1_8 = "_conionDao" ascii //weight: 1
        $x_1_9 = "newCallLogAdded" ascii //weight: 1
        $x_1_10 = "getImo_message" ascii //weight: 1
        $x_1_11 = "getSend_to_server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_AndroidOS_Bahamut_I_2147836300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bahamut.I"
        threat_id = "2147836300"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bahamut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ContactFetchingService" ascii //weight: 1
        $x_1_2 = "index_sms__id" ascii //weight: 1
        $x_1_3 = "CallLogFetchService" ascii //weight: 1
        $x_1_4 = "index_call_logs_call_id" ascii //weight: 1
        $x_1_5 = "_contacts_user_phone" ascii //weight: 1
        $x_1_6 = "index_files_data_file_path" ascii //weight: 1
        $x_1_7 = "SmsFetchService" ascii //weight: 1
        $x_1_8 = "index_user_location_address" ascii //weight: 1
        $x_1_9 = "txt_video_user_name" ascii //weight: 1
        $x_1_10 = "userSmsDao" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

