rule Trojan_AndroidOS_FlokiSpy_A_2147826772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FlokiSpy.A!MTB"
        threat_id = "2147826772"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FlokiSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "backup.spykey-floki.org/add.php" ascii //weight: 1
        $x_1_2 = "secure/movilsecure/com/movilsecure" ascii //weight: 1
        $x_1_3 = "sendTextMessage" ascii //weight: 1
        $x_1_4 = "/MyService2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

