rule Trojan_MSIL_Inveigh_DA_2147916768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Inveigh.DA!MTB"
        threat_id = "2147916768"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Inveigh"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpooferIPv6" ascii //weight: 1
        $x_1_2 = "ListenerIPv6" ascii //weight: 1
        $x_1_3 = "SnifferIPv6" ascii //weight: 1
        $x_1_4 = "DHCPv6 spoofing" ascii //weight: 1
        $x_1_5 = "MDNSPacket" ascii //weight: 1
        $x_20_6 = "LDAP listener" ascii //weight: 20
        $x_1_7 = "HTTPS listener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

