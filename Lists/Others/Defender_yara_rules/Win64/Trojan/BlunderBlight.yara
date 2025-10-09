rule Trojan_Win64_BlunderBlight_A_2147954647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlunderBlight.A"
        threat_id = "2147954647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlunderBlight"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Port for the server to listen on." ascii //weight: 1
        $x_1_2 = "Run the WebSocket SOCKS5 server" ascii //weight: 1
        $x_1_3 = "Run the local SOCKS5 client" ascii //weight: 1
        $x_1_4 = "Install and start the service (default port: 1080)" ascii //weight: 1
        $x_1_5 = "Error: -u (URL) flag is required for client mode." ascii //weight: 1
        $x_1_6 = "Usage: wsocks service <action> [arguments]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

