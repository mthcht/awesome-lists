rule HackTool_Linux_DiscoverPrivateSSHkeys_A_2147768776_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/DiscoverPrivateSSHkeys.A"
        threat_id = "2147768776"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "DiscoverPrivateSSHkeys"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "find / -name id_rsa" wide //weight: 10
        $x_1_2 = "-exec cp --parents {}" wide //weight: 1
        $x_1_3 = "-exec rsync -R {}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_DiscoverPrivateSSHkeys_B_2147768777_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/DiscoverPrivateSSHkeys.B"
        threat_id = "2147768777"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "DiscoverPrivateSSHkeys"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "find / -name id_dsa" wide //weight: 10
        $x_1_2 = "-exec cp --parents {}" wide //weight: 1
        $x_1_3 = "-exec rsync -R {}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

