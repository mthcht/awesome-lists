rule TrojanSpy_AndroidOS_FakeInst_D_2147781468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeInst.D!MTB"
        threat_id = "2147781468"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stealed_sms" ascii //weight: 1
        $x_1_2 = "Reich_SMSGate" ascii //weight: 1
        $x_1_3 = "loadSpam" ascii //weight: 1
        $x_1_4 = "spamlist.txt" ascii //weight: 1
        $x_1_5 = "/flashplayer_/FU;" ascii //weight: 1
        $x_1_6 = "FLASH_PLUGIN_INSTALLATION" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeInst_G_2147820384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeInst.G!MTB"
        threat_id = "2147820384"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Reich_ServerGate" ascii //weight: 1
        $x_1_2 = "getMessages:Executed:HTTP" ascii //weight: 1
        $x_1_3 = "Lcom/adobe/" ascii //weight: 1
        $x_1_4 = "DeviceAdminAdd" ascii //weight: 1
        $x_1_5 = "BotLocation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeInst_E_2147831820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeInst.E!MTB"
        threat_id = "2147831820"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendingLOG" ascii //weight: 1
        $x_1_2 = "tratarMensajeSMS" ascii //weight: 1
        $x_1_3 = "com/espengine/howmake" ascii //weight: 1
        $x_1_4 = "inicioPayerWebpin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeInst_H_2147836762_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeInst.H!MTB"
        threat_id = "2147836762"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "android_asset/legals1" ascii //weight: 1
        $x_1_2 = "androidhitgames.ru/log/start" ascii //weight: 1
        $x_1_3 = "proglayss_Click" ascii //weight: 1
        $x_1_4 = "AnxietyReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeInst_F_2147837754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeInst.F!MTB"
        threat_id = "2147837754"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/google/media/signer" ascii //weight: 1
        $x_1_2 = "pandora00.ru" ascii //weight: 1
        $x_1_3 = "AEScreenOffReceiver" ascii //weight: 1
        $x_1_4 = "SendUserData" ascii //weight: 1
        $x_1_5 = "Contacts3995" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_FakeInst_T_2147847554_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeInst.T!MTB"
        threat_id = "2147847554"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "biprog_Click" ascii //weight: 1
        $x_1_2 = "uncryptedHelloWorld3" ascii //weight: 1
        $x_1_3 = "brules_Click" ascii //weight: 1
        $x_1_4 = "com/Doodle_Physics/game" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

