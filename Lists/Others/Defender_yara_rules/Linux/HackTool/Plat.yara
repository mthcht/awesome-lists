rule HackTool_Linux_Plat_A_2147963318_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Plat.A"
        threat_id = "2147963318"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Plat"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/wangyihang/platypus" ascii //weight: 1
        $x_1_2 = "http2serverConn" ascii //weight: 1
        $x_1_3 = "bodypulltunnelconnect" ascii //weight: 1
        $x_1_4 = "bodypushtunnelcreate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

