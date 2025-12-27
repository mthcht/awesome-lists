rule Ransom_Linux_Trigona_A_2147888249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Trigona.A!MTB"
        threat_id = "2147888249"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IS NOT ENCRYPTED FILE DETECTED!" ascii //weight: 1
        $x_1_2 = "encrypt all data in ESXi mode" ascii //weight: 1
        $x_1_3 = "encrypt all data in NAS mode" ascii //weight: 1
        $x_1_4 = "Can't erase all data. Terminated" ascii //weight: 1
        $x_1_5 = "encrypt_file" ascii //weight: 1
        $x_1_6 = "File in ESXi excluded list" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Linux_Trigona_B_2147888255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Trigona.B!MTB"
        threat_id = "2147888255"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "._locked" ascii //weight: 1
        $x_1_2 = "/erase" ascii //weight: 1
        $x_1_3 = "onepathencryption.pas" ascii //weight: 1
        $x_1_4 = "/shdwn" ascii //weight: 1
        $x_1_5 = "ENCRYPTORERASEFILEBYPATH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Trigona_C_2147902294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Trigona.C!MTB"
        threat_id = "2147902294"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IS NOT ENCRYPTED FILE DETECTED!" ascii //weight: 1
        $x_1_2 = "erase all data" ascii //weight: 1
        $x_1_3 = "Successfully encrypted files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Trigona_D_2147907306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Trigona.D!MTB"
        threat_id = "2147907306"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 31 e8 c6 b8 01 00 48 89 c3 48 89 de 48 ba d8 f6 66 00 00 00 00 00 bf 00 00 00 00 e8 74 bb 01 00 e8 cf 5f 01 00 48 89 df e8 6f ba 01 00 e8 c2 5f 01 00 48 8d 75 f0}  //weight: 1, accuracy: High
        $x_1_2 = {eb 3d 66 44 89 e0 66 41 89 45 08 41 c7 45 18 00 00 00 00 41 8b 55 18 49 8b 45 10 48 01 d0 48 89 c3 0f b7 43 10 41 01 45 18 0f b7 43 10 41 01 45 04 48 8b 03 48 85 c0 74 87 48 89 d8 49 89 c6 4c 89 f0}  //weight: 1, accuracy: High
        $x_1_3 = "File already encrypted or renamed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Trigona_E_2147959090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Trigona.E!MTB"
        threat_id = "2147959090"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "how_to_decrypt.txt" ascii //weight: 1
        $x_1_2 = "vim-cmd vmsvc/getallvms" ascii //weight: 1
        $x_1_3 = "/wipepath" ascii //weight: 1
        $x_1_4 = ".-encrypted" ascii //weight: 1
        $x_1_5 = "vim-cmd vmsvc/power.off" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

