rule Ransom_Linux_HelloKitty_A_2147785360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/HelloKitty.A"
        threat_id = "2147785360"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "HelloKitty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".README_TO_RESTORE" ascii //weight: 1
        $x_1_2 = "Running VM:%ld" ascii //weight: 1
        $x_1_3 = "Find ESXi:%s" ascii //weight: 1
        $x_1_4 = "esxcli vm process kill -t=force -w=%d" ascii //weight: 1
        $x_1_5 = "Usage:%s [-m (10-20-25-33-50) ] Start Path" ascii //weight: 1
        $x_1_6 = "error encrypt: %s rename back:%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

