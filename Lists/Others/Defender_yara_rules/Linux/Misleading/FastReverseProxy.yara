rule Misleading_Linux_FastReverseProxy_A_343484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Linux/FastReverseProxy.A!MTB"
        threat_id = "343484"
        type = "Misleading"
        platform = "Linux: Linux platform"
        family = "FastReverseProxy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fatedier/frp/models/msg" ascii //weight: 1
        $x_1_2 = "fatedier/frp/cmd/frpc/sub" ascii //weight: 1
        $x_1_3 = "frp/vendor/github.com/spf13/cobra" ascii //weight: 1
        $x_1_4 = "frp/vendor/github.com/vaughan0/go-ini" ascii //weight: 1
        $x_1_5 = "*config.BindInfoConf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

