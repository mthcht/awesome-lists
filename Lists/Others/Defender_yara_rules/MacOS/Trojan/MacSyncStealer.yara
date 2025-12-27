rule Trojan_MacOS_MacSyncStealer_A_2147960097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/MacSyncStealer.A!MTB"
        threat_id = "2147960097"
        type = "Trojan"
        platform = "MacOS: "
        family = "MacSyncStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttps://gatemaden.space/curl/" ascii //weight: 1
        $x_1_2 = "/tmp/runner.code" ascii //weight: 1
        $x_1_3 = "/Library/Logs/UserSyncWorker.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

