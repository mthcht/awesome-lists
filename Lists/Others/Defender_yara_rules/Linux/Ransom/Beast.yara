rule Ransom_Linux_Beast_A_2147925488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Beast.A!MTB"
        threat_id = "2147925488"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Beast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ENCRYPTER: DAEMON" ascii //weight: 1
        $x_1_2 = "beast.log" ascii //weight: 1
        $x_1_3 = "vim-cmd vmsvc/getallvms 2>&1" ascii //weight: 1
        $x_1_4 = {2d 70 3d 35 20 2d 65 3d ?? 42 45 41 53 54 57 41 53 48 45 52 45 ?? 20 2d 78 3d ?? 52 45 41 44 4d 45 2e 54 58 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

