rule Ransom_Linux_MoneyMessage_K_2147845997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/MoneyMessage.K!MTB"
        threat_id = "2147845997"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "MoneyMessage"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "esxcli --formatter=csv --format-param=fields==" ascii //weight: 1
        $x_1_2 = "esxcli vm process kill --type=force --world-id=" ascii //weight: 1
        $x_1_3 = "vm process list | awk -F " ascii //weight: 1
        $x_1_4 = "crypt_only_these_directories" ascii //weight: 1
        $x_1_5 = "moneypunct_byname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

