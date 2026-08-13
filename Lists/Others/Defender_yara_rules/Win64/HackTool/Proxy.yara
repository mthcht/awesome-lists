rule HackTool_Win64_Proxy_NZA_2147976096_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Proxy.NZA!MTB"
        threat_id = "2147976096"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Proxy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Usage: yuze" ascii //weight: 1
        $x_2_2 = "[+] Starting reverse Proxy" ascii //weight: 2
        $x_1_3 = "[-] Error: Unable to start port forward listener on port" ascii //weight: 1
        $x_1_4 = "[+] Established forward tunnel between client %s:%d and target %s:%d" ascii //weight: 1
        $x_1_5 = "-c, --connect_server  Set reverse proxy connect server" ascii //weight: 1
        $x_1_6 = "-s, --socksport       Set SOCKS port for Reverse Proxy" ascii //weight: 1
        $x_2_7 = "[+] Error_Report@github P001" ascii //weight: 2
        $x_1_8 = {5f 20 20 20 5f 20 5f 20 20 20 5f 20 5f 5f 5f 5f 5f 5f 5f 20 0a 00 00 7c 20 7c 20 7c 20 7c 20 7c 20 7c 20 7c 5f 20 20 2f 20 5f 20 5c 0a 00 00 7c 20 7c 5f 7c 20 7c 20 7c 5f 7c 20 7c 2f 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

