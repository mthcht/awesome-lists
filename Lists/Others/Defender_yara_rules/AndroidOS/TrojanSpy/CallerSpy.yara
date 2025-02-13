rule TrojanSpy_AndroidOS_CallerSpy_A_2147789214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/CallerSpy.A"
        threat_id = "2147789214"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "CallerSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "updateCallLogsList" ascii //weight: 1
        $x_1_2 = "sync_data_locally" ascii //weight: 1
        $x_1_3 = "uploadEnviormentRecordings" ascii //weight: 1
        $x_1_4 = "updateCallRecordings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

