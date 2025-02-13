rule TrojanSpy_AndroidOS_SmsReplicator_A_2147808881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsReplicator.A"
        threat_id = "2147808881"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsReplicator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/SMSReplicatorSecret;" ascii //weight: 1
        $x_1_2 = "red4life" ascii //weight: 1
        $x_1_3 = "DBforwardingNo" ascii //weight: 1
        $x_1_4 = "shady.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

