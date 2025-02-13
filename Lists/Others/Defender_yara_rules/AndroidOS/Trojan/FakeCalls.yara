rule Trojan_AndroidOS_FakeCalls_H_2147845483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeCalls.H"
        threat_id = "2147845483"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeCalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ComSmsActivity" ascii //weight: 2
        $x_2_2 = "CALL_SOURCE_FORWARDING_HANG_UP" ascii //weight: 2
        $x_2_3 = "KEY_IS_FORCED_CALL" ascii //weight: 2
        $x_2_4 = "KEY_CLOSE_TCALL_ALERT_WINDOW" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

