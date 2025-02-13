rule Trojan_AndroidOS_Stealer_A_2147745617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Stealer.A!MTB"
        threat_id = "2147745617"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ls/s/AlrmRc;" ascii //weight: 1
        $x_1_2 = "Ls/s/SRc;" ascii //weight: 1
        $x_1_3 = "disableInboxSmsFilter" ascii //weight: 1
        $x_1_4 = "installApp" ascii //weight: 1
        $x_1_5 = "startHider" ascii //weight: 1
        $x_1_6 = "getDeviceInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Stealer_B_2147765517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Stealer.B!MTB"
        threat_id = "2147765517"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "html/app/MainActivity" ascii //weight: 1
        $x_1_2 = "getDeviceInformation" ascii //weight: 1
        $x_1_3 = "startHider" ascii //weight: 1
        $x_1_4 = "disableInboxSmsFilter" ascii //weight: 1
        $x_1_5 = "installApp" ascii //weight: 1
        $x_1_6 = "sendDelayedSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Stealer_C_2147787208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Stealer.C!MTB"
        threat_id = "2147787208"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "removeAllSmsFilters" ascii //weight: 1
        $x_1_2 = "catchSmsList" ascii //weight: 1
        $x_1_3 = "sendContactsToServer" ascii //weight: 1
        $x_1_4 = "Lsystem/service/SmsReciver" ascii //weight: 1
        $x_1_5 = "removeAllCatchFilters" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

