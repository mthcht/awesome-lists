rule Trojan_AndroidOS_LoanSpy_A_2147836463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/LoanSpy.A"
        threat_id = "2147836463"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "LoanSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "calling syncSMS" ascii //weight: 2
        $x_2_2 = "ManageTextMessagesService" ascii //weight: 2
        $x_2_3 = "DeviceStatusSyncUtils" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

