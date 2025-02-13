rule Trojan_MSIL_Resocks_A_2147767226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Resocks.A"
        threat_id = "2147767226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Resocks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sq3b1M04Vxyw+SU5WTtXkOgIXyNuo1C1DveLuNN7eaujsdlBh81MJ2Dgb1oALnWUoD9tZiDv4if+Ikx0673wUw==" wide //weight: 2
        $x_2_2 = "ReverseSocksClient\\ReverseSocksClient\\obj\\Release\\ReverseSocksClient.pdb" ascii //weight: 2
        $x_2_3 = "PACKET_PROXY_CLIENT_SHUTDOWN" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

