rule Ransom_AndroidOS_SLocker_E_2147832190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/SLocker.E!MTB"
        threat_id = "2147832190"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "SLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 07 54 77 10 00 15 08 02 7f 6e 20 ?? ?? 87 00 07 07}  //weight: 10, accuracy: Low
        $x_1_2 = {54 20 1f 00 54 00 22 00 6e 10 ?? ?? 00 00 0c 00 72 10 ?? ?? 00 00 0c 00}  //weight: 1, accuracy: Low
        $x_10_3 = {1a 01 75 00 6e 20 ?? ?? 10 00 0c 00 6e 10 ?? ?? 00 00 0c 00 1a 01 e1 00}  //weight: 10, accuracy: Low
        $x_1_4 = {07 78 1a 09 8e 00 6e 20 ?? ?? 98 00 0c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_AndroidOS_SLocker_F_2147852376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/SLocker.F!MTB"
        threat_id = "2147852376"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "SLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tx/qq898507339/bzy9" ascii //weight: 1
        $x_1_2 = "getCustomClassLoader" ascii //weight: 1
        $x_1_3 = "getACall" ascii //weight: 1
        $x_1_4 = "/SmsReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_AndroidOS_SLocker_G_2147911999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/SLocker.G!MTB"
        threat_id = "2147911999"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "SLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptDirectory" ascii //weight: 1
        $x_1_2 = "com/adobe/videoprayer" ascii //weight: 1
        $x_1_3 = "LockerService" ascii //weight: 1
        $x_1_4 = "getAndSendDeviceData" ascii //weight: 1
        $x_1_5 = "sendSMStoContacts" ascii //weight: 1
        $x_1_6 = "getBrowserHistory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

