rule TrojanSpy_AndroidOS_RewardSteal_A_2147837897_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.A!MTB"
        threat_id = "2147837897"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Cheakpermission" ascii //weight: 1
        $x_1_2 = "cardNumber" ascii //weight: 1
        $x_1_3 = {4c 63 6f 6d 2f 72 65 77 61 72 64 73 2f [0-4] 2f 53 6d 73 52 65 63 65 69 76 65 72}  //weight: 1, accuracy: Low
        $x_1_4 = "finishAffinity" ascii //weight: 1
        $x_1_5 = "loaddLastScreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_RewardSteal_C_2147841245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.C!MTB"
        threat_id = "2147841245"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "S1m2s3L4i5s6t7n8e9r0" ascii //weight: 1
        $x_5_2 = "/save_sms0.php" ascii //weight: 5
        $x_5_3 = "Lcom/example/myapplication/SmsReceiver" ascii //weight: 5
        $x_5_4 = "000webhostapp.com/" ascii //weight: 5
        $x_1_5 = "sendSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_RewardSteal_B_2147841564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.B!MTB"
        threat_id = "2147841564"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.mykycandroid." ascii //weight: 5
        $x_5_2 = "com/hdreward/points/MainActivity" ascii //weight: 5
        $x_1_3 = "&from=app" ascii //weight: 1
        $x_1_4 = "sendData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_RewardSteal_F_2147842154_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.F!MTB"
        threat_id = "2147842154"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.imranhasmi." ascii //weight: 5
        $x_5_2 = "com/allservicecenter/android/MainActivity" ascii //weight: 5
        $x_1_3 = "&from=app" ascii //weight: 1
        $x_1_4 = "sendData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_RewardSteal_D_2147843265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.D!MTB"
        threat_id = "2147843265"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "submitContactMsgData" ascii //weight: 1
        $x_1_2 = "get_msg_and_contact" ascii //weight: 1
        $x_1_3 = "Lcom/app/bonusreward" ascii //weight: 1
        $x_1_4 = "PresenterSMS" ascii //weight: 1
        $x_1_5 = "submitFormData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_RewardSteal_E_2147850538_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.E!MTB"
        threat_id = "2147850538"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adpter_getuset" ascii //weight: 1
        $x_1_2 = "senderNoti" ascii //weight: 1
        $x_1_3 = "server_down" ascii //weight: 1
        $x_1_4 = "diviceblock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_RewardSteal_G_2147905722_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.G!MTB"
        threat_id = "2147905722"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttps://filipkatrt.in/admin" ascii //weight: 1
        $x_1_2 = "MessageResever" ascii //weight: 1
        $x_1_3 = "pussword" ascii //weight: 1
        $x_1_4 = "com/example/bill_updatetrygreert354rt534t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_RewardSteal_H_2147910825_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.H!MTB"
        threat_id = "2147910825"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttps://panel247.xyz/" ascii //weight: 1
        $x_1_2 = "api/messege.php" ascii //weight: 1
        $x_1_3 = "card_number" ascii //weight: 1
        $x_1_4 = "api/insert.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_RewardSteal_I_2147914095_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.I!MTB"
        threat_id = "2147914095"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/userMessage.php" ascii //weight: 1
        $x_1_2 = "/getAppData.php" ascii //weight: 1
        $x_1_3 = "sendDataToServer" ascii //weight: 1
        $x_5_4 = "Lcom/idbibankou/idbibank" ascii //weight: 5
        $x_5_5 = "Lcom/load/loan" ascii //weight: 5
        $x_1_6 = "readOldSmsMessages" ascii //weight: 1
        $x_1_7 = "/appReg.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_RewardSteal_J_2147923681_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.J!MTB"
        threat_id = "2147923681"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 b0 06 00 6e 10 12 00 00 00 0c 00 6e 10 39 00 00 00 0c 00 6e 10 3b 00 00 00 0c 00 54 b1 07 00 6e 10 12 00 01 00 0c 01 6e 10 39 00 01 00 0c 01 6e 10 3b 00 01 00 0c 01 6e 10 3a 00 00 00 0a 02 12 03 39 02 5f 00 6e 10 3a 00 01 00 0a 02 38 02 03 00 28 57}  //weight: 1, accuracy: High
        $x_1_2 = {6e 10 06 00 0d 00 0c 00 38 00 55 00 1a 01 93 00 6e 20 07 00 10 00 0c 01 1f 01 32 00 38 01 4b 00 21 12 12 03 35 23 47 00 46 04 01 03 07 45 1f 05 30 00 71 10 0c 00 05 00 0c 05 6e 10 0d 00 05 00 0c 06 6e 10 0e 00 05 00 0c 07 22 08 2c 00 70 10 3c 00 08 00 1a 09 4c 00 6e 20 3d 00 98 00 0c 08 6e 20 3d 00 68 00 0c 08 6e 10 3e 00 08 00 0c 08 1a 09 4e 00 71 20 0f 00 89 00 22 08 2c 00 70 10 3c 00 08 00 1a 0a 48 00 6e 20 3d 00 a8 00 0c 08 6e 20 3d 00 78 00 0c 08 6e 10 3e 00 08 00 0c 08 71 20 0f 00 89 00 70 20 2f 00 7b 00 d8 03 03 01 28 ba}  //weight: 1, accuracy: High
        $x_1_3 = "com/atm/card/MainActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_RewardSteal_K_2147925721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.K!MTB"
        threat_id = "2147925721"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendMessageToTelegramBots" ascii //weight: 1
        $x_1_2 = "processSmsReceived" ascii //weight: 1
        $x_1_3 = "fetchForwardingNumber" ascii //weight: 1
        $x_1_4 = "com/cfhd/com/SMSReceiver" ascii //weight: 1
        $x_1_5 = "initializeSMSForwarder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_RewardSteal_AA_2147940013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewardSteal.AA!MTB"
        threat_id = "2147940013"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1a 01 b9 02 08 13 02 00 08 02 12 00 72 30 72 01 12 07 02 12 03 00 1a 03 63 02 72 30 72 01 32 08 08 14 05 00 1a 05 f6 02 72 30 72 01 52 0f 08 15 02 00 71 00 23 01 00 00 0c 02 08 16 06 00 1a 06 db 02 6e 20 24 01 62 00 0c 02 6e 20 1f 01 92 00 0c 02 08 17 0b 00 1a 0b 66 02 6e 20 1f 01 b2 00 0c 02 6e 20 21 01 a2 00 71 00 23 01 00 00 0c 0b 6e 20 24 01 6b 00 0c 0b 6e 20 1f 01 9b 00 0c 0b 08 18 02 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 20 1f 01 16 00 0c 01 6e 20 21 01 71 00 6e 20 1f 01 36 00 0c 01 6e 20 21 01 81 00 6e 20 1f 01 56 00 0c 01 6e 20 21 01 f1 00 d8 04 04 01 08 00 1a 00 08 01 10 00 02 03 12 00 08 02 13 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

