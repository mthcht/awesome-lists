rule Trojan_Linux_RShell_A_2147931809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/RShell.A!MTB"
        threat_id = "2147931809"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "RShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/revshell/client/host.go" ascii //weight: 1
        $x_1_2 = "/client.(*Host).handleCommand" ascii //weight: 1
        $x_1_3 = "red.team/go-red/dns" ascii //weight: 1
        $x_1_4 = "proxy.serveForward" ascii //weight: 1
        $x_1_5 = "icmptunnel.newClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

