rule Misleading_Linux_FRP_E_347592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Linux/FRP.E!MTB"
        threat_id = "347592"
        type = "Misleading"
        platform = "Linux: Linux platform"
        family = "FRP"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fatedier/frp/cmd/frpc/sub.runClient" ascii //weight: 1
        $x_1_2 = "frp/cmd/frpc/sub/xtcp.go" ascii //weight: 1
        $x_1_3 = "frp/client/proxy/proxy_manager.go" ascii //weight: 1
        $x_1_4 = "fatedier/frp/client/proxy.NewProxy" ascii //weight: 1
        $x_1_5 = "remote_port" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Misleading_Linux_FRP_B_356202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Linux/FRP.B!MTB"
        threat_id = "356202"
        type = "Misleading"
        platform = "Linux: Linux platform"
        family = "FRP"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/fatedier/frp/" ascii //weight: 1
        $x_1_2 = "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size" ascii //weight: 1
        $x_1_3 = "KeyLogWriter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

