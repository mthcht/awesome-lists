rule Trojan_MacOS_FakeHelp_DA_2147970252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/FakeHelp.DA!MTB"
        threat_id = "2147970252"
        type = "Trojan"
        platform = "MacOS: "
        family = "FakeHelp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.collectSystemInfo" ascii //weight: 1
        $x_1_2 = "main.collectIPAddresses" ascii //weight: 1
        $x_1_3 = "main.dnsBeacon" ascii //weight: 1
        $x_1_4 = "main.httpCallback.deferwrap1" ascii //weight: 1
        $x_1_5 = "main.writePersistenceMarker" ascii //weight: 1
        $x_1_6 = "/payload/main.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

