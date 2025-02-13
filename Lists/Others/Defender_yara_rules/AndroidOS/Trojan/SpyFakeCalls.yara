rule Trojan_AndroidOS_SpyFakeCalls_A_2147793450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyFakeCalls.A"
        threat_id = "2147793450"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyFakeCalls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "|*telEntityArrayList*|" ascii //weight: 5
        $x_5_2 = "|*callEntity*|" ascii //weight: 5
        $x_5_3 = "|*apkEntity*|" ascii //weight: 5
        $x_1_4 = "uploadCallLog" ascii //weight: 1
        $x_1_5 = "uploadDeviceInfo" ascii //weight: 1
        $x_1_6 = "uploadRecordingFile" ascii //weight: 1
        $x_1_7 = "updateCommandRecordingStatus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

