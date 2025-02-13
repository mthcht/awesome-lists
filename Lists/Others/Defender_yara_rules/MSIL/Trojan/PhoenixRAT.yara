rule Trojan_MSIL_PhoenixRAT_A_2147842982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhoenixRAT.A!MTB"
        threat_id = "2147842982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhoenixRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ZlxL5VcDxDegkIjCzfv1LxgdDRGHBnFWmmVfSBkwelY=" wide //weight: 2
        $x_2_2 = "6zIg8sRJqmBqn2EJNXVlrg==" wide //weight: 2
        $x_2_3 = "poOTSlK3L0DkDKdhzKCCcQ==" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

