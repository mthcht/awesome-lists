rule Trojan_MSIL_TukTuk_AMTB_2147969376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TukTuk!AMTB"
        threat_id = "2147969376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TukTuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "g8way.io" ascii //weight: 1
        $x_1_2 = "agent_id" ascii //weight: 1
        $x_1_3 = "heartbeat" ascii //weight: 1
        $x_1_4 = "Dropbox token refresh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

