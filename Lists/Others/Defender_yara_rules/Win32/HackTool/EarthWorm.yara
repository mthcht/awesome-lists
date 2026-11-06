rule HackTool_Win32_EarthWorm_A_2147951343_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/EarthWorm.A"
        threat_id = "2147951343"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "EarthWorm"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exit socks_port_server" ascii //weight: 1
        $x_1_2 = "ssocksd , rcsocks , rssocks" ascii //weight: 1
        $x_1_3 = "lcx_listen , lcx_tran , lcx_slave" ascii //weight: 1
        $x_1_4 = "You can create a SOCKS5 server like this" ascii //weight: 1
        $x_1_5 = "Something error on read URL" ascii //weight: 1
        $x_1_6 = "--> %3d <-- (close)used/unused  %d/%d" ascii //weight: 1
        $x_1_7 = "ssocksd 0.0.0.0:%d <--[%4d usec]--> socks server" ascii //weight: 1
        $x_1_8 = "init cmd_server_for_rc here" ascii //weight: 1
        $x_1_9 = "Error on connect %s:%d [proto_init_cmd_rcsocket]" ascii //weight: 1
        $x_1_10 = "CONFIRM_YOU_ARE_SOCK_CLIENT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule HackTool_Win32_EarthWorm_SA_2147961273_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/EarthWorm.SA"
        threat_id = "2147961273"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "EarthWorm"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lcx_tran --listenport" ascii //weight: 1
        $x_1_2 = "ssocksd --listenport" ascii //weight: 1
        $x_1_3 = "lcx_slave --refhost [ref_ip] --refport" ascii //weight: 1
        $x_1_4 = "rcsocks" ascii //weight: 1
        $x_1_5 = "rssocks" ascii //weight: 1
        $x_1_6 = "error on connect %s:%d [proto_init_cmd_rcsocket]" ascii //weight: 1
        $x_3_7 = "http://rootkiter.com/earthwrom/" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_EarthWorm_AE_2147981602_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/EarthWorm.AE!MTB"
        threat_id = "2147981602"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "EarthWorm"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Earthworm is a network agent tool" ascii //weight: 4
        $x_3_2 = "rootkiter : The creator" ascii //weight: 3
        $x_2_3 = "EarthWrom" ascii //weight: 2
        $x_1_4 = "You can create a SOCKS5 server like this" ascii //weight: 1
        $x_1_5 = "You can create a Socks5 proxy server in the Intranet or Extranet" ascii //weight: 1
        $x_1_6 = "listen" ascii //weight: 1
        $x_1_7 = "socket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

