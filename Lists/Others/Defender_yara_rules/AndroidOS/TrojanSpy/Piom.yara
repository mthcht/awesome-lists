rule TrojanSpy_AndroidOS_Piom_D_2147798307_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Piom.D"
        threat_id = "2147798307"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GenerateUrlKnock" ascii //weight: 1
        $x_1_2 = "setHttpVer" ascii //weight: 1
        $x_1_3 = "startLoaderActivity" ascii //weight: 1
        $x_1_4 = "start_work_me" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Piom_AT_2147812374_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Piom.AT"
        threat_id = "2147812374"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getContacsDao" ascii //weight: 1
        $x_1_2 = "DeleteAllSms" ascii //weight: 1
        $x_1_3 = "_infoWhatsappMessage" ascii //weight: 1
        $x_1_4 = "https://r4dc3btbyzip0edkbykb1qteulwb.de" ascii //weight: 1
        $x_1_5 = "Lcom/custom/vcopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Piom_C_2147816136_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Piom.C!MTB"
        threat_id = "2147816136"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ir.a.testfirebase" ascii //weight: 1
        $x_1_2 = "sajjad4580" ascii //weight: 1
        $x_1_3 = "register: commed" ascii //weight: 1
        $x_1_4 = "sendmultisms" ascii //weight: 1
        $x_1_5 = "appSmsLogger" ascii //weight: 1
        $x_1_6 = "/UploadSms.php" ascii //weight: 1
        $x_1_7 = "/GetLink.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_Piom_E_2147821037_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Piom.E!MTB"
        threat_id = "2147821037"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LocalContacts" ascii //weight: 1
        $x_1_2 = "LocalImage" ascii //weight: 1
        $x_1_3 = "LocalMessage" ascii //weight: 1
        $x_1_4 = "getSmsbody" ascii //weight: 1
        $x_1_5 = "getPhoneNumber" ascii //weight: 1
        $x_1_6 = "/api/uploads/api" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Piom_F_2147836735_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Piom.F!MTB"
        threat_id = "2147836735"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Piom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/neonet/app/reader/MainActivity" ascii //weight: 1
        $x_1_2 = "com.smodj.app.smstotelegram" ascii //weight: 1
        $x_1_3 = "verificarPermisos" ascii //weight: 1
        $x_1_4 = "setWebViewClient" ascii //weight: 1
        $x_1_5 = "unsentMsg" ascii //weight: 1
        $x_1_6 = "sendToTelegramAPI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

