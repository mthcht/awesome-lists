rule Ransom_Linux_Embargo_A_2147947444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Embargo.A!MTB"
        threat_id = "2147947444"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Embargo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "embargo::crypter" ascii //weight: 1
        $x_1_2 = "vim-cmd vmsvc/getallvms" ascii //weight: 1
        $x_1_3 = "full_encrypt_ext" ascii //weight: 1
        $x_1_4 = "xargs -n1 vim-cmd vmsvc/snapshot.removeall" ascii //weight: 1
        $x_1_5 = "esxcli vm process kill --type=force --world-id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

