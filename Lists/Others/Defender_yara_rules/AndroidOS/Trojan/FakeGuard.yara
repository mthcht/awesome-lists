rule Trojan_AndroidOS_FakeGuard_A_2147668295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeGuard.A"
        threat_id = "2147668295"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeGuard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendMessage() Connect Error!!" ascii //weight: 1
        $x_1_2 = "SMS From1:" ascii //weight: 1
        $x_1_3 = "Reseting:" ascii //weight: 1
        $x_1_4 = "SpamBlocker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

