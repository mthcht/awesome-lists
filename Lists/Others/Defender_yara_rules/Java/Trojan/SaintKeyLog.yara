rule Trojan_Java_SaintKeyLog_2147744720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/SaintKeyLog!MTB"
        threat_id = "2147744720"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "SaintKeyLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "saint/screenshot/PK" ascii //weight: 1
        $x_1_2 = "saint/webcam/PK" ascii //weight: 1
        $x_1_3 = "saint/keylogger/PK" ascii //weight: 1
        $x_1_4 = "saint/email/SendEmail" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

