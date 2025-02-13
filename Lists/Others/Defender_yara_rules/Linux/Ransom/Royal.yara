rule Ransom_Linux_Royal_A_2147840762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Royal.A!MTB"
        threat_id = "2147840762"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Royal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "esxcli vm process kill --type=hard --world-id" ascii //weight: 1
        $x_1_2 = ".royal_w" ascii //weight: 1
        $x_1_3 = "royal_log_" ascii //weight: 1
        $x_1_4 = "/readme" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

