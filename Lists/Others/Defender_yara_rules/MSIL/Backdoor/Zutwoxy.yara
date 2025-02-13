rule Backdoor_MSIL_Zutwoxy_A_2147654736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Zutwoxy.A"
        threat_id = "2147654736"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zutwoxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UDP Flood started!" wide //weight: 1
        $x_1_2 = "SYN Flood started!" wide //weight: 1
        $x_1_3 = "Cam disconnected!" wide //weight: 1
        $x_1_4 = "Keylog sub started!" wide //weight: 1
        $x_1_5 = "Proxy Flood started!" wide //weight: 1
        $x_1_6 = "HTTP Flood started!" wide //weight: 1
        $x_1_7 = "TCP Flood failed!" wide //weight: 1
        $x_1_8 = "Block website failed!" wide //weight: 1
        $x_1_9 = "Passwords sent!" wide //weight: 1
        $x_1_10 = "BOTKILLER" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

