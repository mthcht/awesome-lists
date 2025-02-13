rule Misleading_MacOS_FRP_A_361239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:MacOS/FRP.A!MTB"
        threat_id = "361239"
        type = "Misleading"
        platform = "MacOS: "
        family = "FRP"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/fatedier/frp/cmd/frpc/main.go" ascii //weight: 1
        $x_1_2 = "/reverseproxy.go" ascii //weight: 1
        $x_1_3 = "runtime.persistentalloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

