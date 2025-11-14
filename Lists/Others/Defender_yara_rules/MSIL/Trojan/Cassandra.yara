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

rule Trojan_MSIL_Cassandra_GZF_2147954333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cassandra.GZF!MTB"
        threat_id = "2147954333"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cassandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "F O X g s" ascii //weight: 1
        $x_1_3 = "!!J!R!\\!" ascii //weight: 1
        $x_1_4 = "! \"1\"J\"_\"z\"" ascii //weight: 1
        $x_1_5 = "bfjlXZoHL" ascii //weight: 1
        $x_1_6 = "GetProcessById" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cassandra_EXP_2147957514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cassandra.EXP!MTB"
        threat_id = "2147957514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cassandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DriverFix Pro.dll" ascii //weight: 1
        $x_1_2 = "System driver repair utility" ascii //weight: 1
        $x_1_3 = "2.3.1.789" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

