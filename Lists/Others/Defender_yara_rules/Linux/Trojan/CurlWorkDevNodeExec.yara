rule Trojan_Linux_CurlWorkDevNodeExec_Z_2147968714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CurlWorkDevNodeExec.Z!MTB"
        threat_id = "2147968714"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CurlWorkDevNodeExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "python" wide //weight: 1
        $x_1_2 = "curl http" wide //weight: 1
        $x_1_3 = "workers.dev" wide //weight: 1
        $x_1_4 = "| node" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

