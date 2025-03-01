rule TrojanSpy_AndroidOS_Smsthief_AR_2147843425_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Smsthief.AR!MTB"
        threat_id = "2147843425"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/ll/contactdemo" ascii //weight: 1
        $x_1_2 = "ContactBean{truename=" ascii //weight: 1
        $x_1_3 = "/index.php/Ajax/get_contacts" ascii //weight: 1
        $x_1_4 = "upLoadSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Smsthief_AC_2147890540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Smsthief.AC!MTB"
        threat_id = "2147890540"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsreciver.g4ctsneogzmf7ndrxzld8gfewebq20ef2e.org/recive.php" ascii //weight: 1
        $x_1_2 = "sendSMS" ascii //weight: 1
        $x_1_3 = "getIPAddress" ascii //weight: 1
        $x_1_4 = "getDomain.php?srv" ascii //weight: 1
        $x_1_5 = "koronapay.cash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Smsthief_BA_2147902753_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Smsthief.BA!MTB"
        threat_id = "2147902753"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendMessage?parse_mode=markdown&chat_id=" ascii //weight: 1
        $x_1_2 = "ReceiveSms" ascii //weight: 1
        $x_1_3 = "com/example/appjava" ascii //weight: 1
        $x_1_4 = "smsMessageArr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

