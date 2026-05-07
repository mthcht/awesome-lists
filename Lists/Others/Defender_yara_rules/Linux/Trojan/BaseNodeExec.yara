rule Trojan_Linux_BaseNodeExec_Z_2147968713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/BaseNodeExec.Z!MTB"
        threat_id = "2147968713"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "BaseNodeExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "| base64 -d | node" wide //weight: 1
        $x_1_2 = "echo" wide //weight: 1
        $x_1_3 = "python" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

