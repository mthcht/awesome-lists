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

rule Trojan_MSIL_Cassandra_SM_2147960300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cassandra.SM!MTB"
        threat_id = "2147960300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cassandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CasharkZoot.dll" ascii //weight: 1
        $x_1_2 = "CashToEarn is a rewards platform where you earn cash or crypto by completing tasks like surveys" ascii //weight: 1
        $x_1_3 = "2.3.9.8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cassandra_SB_2147960301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cassandra.SB!MTB"
        threat_id = "2147960301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cassandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BuildCalc Pro.dll" ascii //weight: 1
        $x_1_2 = "Structural engineering calculation software" ascii //weight: 1
        $x_1_3 = "StructureTech Solutions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cassandra_WE_2147965367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cassandra.WE!MTB"
        threat_id = "2147965367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cassandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 04 11 05 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 28 ?? 00 00 0a 16 07 08 1a 28 ?? 00 00 0a 08 1a 58 0c 11 05 17 58 13 05 11 05 06}  //weight: 5, accuracy: Low
        $x_2_2 = {02 11 04 09 6f ?? 00 00 0a 13 05 08 11 04 09 11 05 6f ?? 00 00 0a 16}  //weight: 2, accuracy: Low
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cassandra_AKP_2147966995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cassandra.AKP!MTB"
        threat_id = "2147966995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cassandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Calc.dll" ascii //weight: 1
        $x_1_2 = "Real-time system health and performance metrics analyzer" ascii //weight: 1
        $x_1_3 = "SystemStatus Calculator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cassandra_GN_2147967863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cassandra.GN!MTB"
        threat_id = "2147967863"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cassandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gebocinal" ascii //weight: 1
        $x_1_2 = "Part inventories, paint mixing ratios via color math" ascii //weight: 1
        $x_1_3 = "Habnira" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

