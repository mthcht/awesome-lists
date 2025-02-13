rule HackTool_Linux_SSLDos_A_2147921688_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SSLDos.A!MTB"
        threat_id = "2147921688"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SSLDos"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SSL_renegotiate" ascii //weight: 1
        $x_1_2 = "thc-ssl-dos.c" ascii //weight: 1
        $x_1_3 = "ssl_handshake_io" ascii //weight: 1
        $x_1_4 = "%d tcp_connect_io" ascii //weight: 1
        $x_1_5 = "./thc-ssl-dos [options] <ip> <port>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

