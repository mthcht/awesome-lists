rule Trojan_MSIL_DNSChanger_E_2147717894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DNSChanger.E"
        threat_id = "2147717894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DNSChanger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://dns-service1.ddns.net:8888" wide //weight: 1
        $x_1_2 = "http://dns-service2.ddns.net:8888" wide //weight: 1
        $x_1_3 = "http://dns-service3.ddns.net:8888" wide //weight: 1
        $x_1_4 = "http://mattyeh.com:8888" wide //weight: 1
        $x_1_5 = "http://cindytop.com:8888" wide //weight: 1
        $x_1_6 = "http://richardpop.com:8888" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

