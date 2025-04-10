rule Trojan_MSIL_Cassandra_GPPD_2147938488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cassandra.GPPD!MTB"
        threat_id = "2147938488"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cassandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {91 9c 61 d2 81 01 00 00 01 11 ?? 1f ?? 91 13 10}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

