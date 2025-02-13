rule Trojan_AndroidOS_Soceng_PT_2147927141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Soceng.PT"
        threat_id = "2147927141"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Soceng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyServices$Async_sendSMS" ascii //weight: 1
        $x_1_2 = "UNINSTALL_PACKAGE_EXISTED_PWD" ascii //weight: 1
        $x_1_3 = "addSMSIntoInbox" ascii //weight: 1
        $x_1_4 = "deactivateDeviceAdmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

