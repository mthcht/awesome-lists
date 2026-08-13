rule HackTool_Linux_Proxy_NZC_2147976098_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Proxy.NZC!MTB"
        threat_id = "2147976098"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Proxy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Usage: yuze" ascii //weight: 1
        $x_2_2 = "[+] Starting reverse Proxy" ascii //weight: 2
        $x_1_3 = "[-] Error: Unable to start port forward listener on port" ascii //weight: 1
        $x_1_4 = "[+] Established forward tunnel between client %s:%d and target %s:%d" ascii //weight: 1
        $x_1_5 = "-c, --connect_server  Set reverse proxy connect server" ascii //weight: 1
        $x_1_6 = "-s, --socksport       Set SOCKS port for Reverse Proxy" ascii //weight: 1
        $x_2_7 = "[+] Error_Report@github P001" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

