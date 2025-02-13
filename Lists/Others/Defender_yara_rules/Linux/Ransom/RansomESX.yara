rule Ransom_Linux_RansomESX_A_2147916718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/RansomESX.A"
        threat_id = "2147916718"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "RansomESX"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "esxcli vm process kill -t=soft -w=%d" ascii //weight: 1
        $x_1_2 = "esxcli vm process kill -t=force -w=%d" ascii //weight: 1
        $x_1_3 = "esxcli vm process kill -t=hard -w=%d" ascii //weight: 1
        $x_1_4 = "esxcli vm process list" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

