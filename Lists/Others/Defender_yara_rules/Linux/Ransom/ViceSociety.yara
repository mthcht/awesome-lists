rule Ransom_Linux_ViceSociety_D_2147831034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/ViceSociety.D!MTB"
        threat_id = "2147831034"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "ViceSociety"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR FILES HAVE BEEN ENCRYPTED BY VICE SOCIETY" ascii //weight: 1
        $x_1_2 = "All your files, PVE/VMWare infrastructure and backups have been encrypted" ascii //weight: 1
        $x_1_3 = ".README_TO_RESTORE" ascii //weight: 1
        $x_1_4 = "Usage:%s [-m (10-20-25-33-50) ] Start Path" ascii //weight: 1
        $x_1_5 = "File Locked:%s PID:%d" ascii //weight: 1
        $x_1_6 = ".xxxx" ascii //weight: 1
        $x_1_7 = ".crypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Linux_ViceSociety_DB_2147832796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/ViceSociety.DB!MTB"
        threat_id = "2147832796"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "ViceSociety"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".v-society" ascii //weight: 1
        $x_1_2 = "Usage:%s [-m (10-20-25-33-50) ] Start Path" ascii //weight: 1
        $x_1_3 = {48 8d 85 f0 ef ff ff 48 89 c7 e8 b0 1e 00 00 89 85 54 ef ff ff 83 bd 54 ef ff ff 00 0f 84 c0 01 00 00 48 8b 05 c3 84 20 00 48 85 c0 74 28 48 8b 05 b7 84 20 00 8b 8d 54 ef ff ff 48 8d 95 f0 ef ff ff 48 8d 35 44 4d 00 00 48 89 c7 b8}  //weight: 1, accuracy: High
        $x_1_4 = {48 8b 95 60 ef ff ff 48 8d 85 f0 ef ff ff 48 89 d6 48 89 c7 e8 91 ec ff ff 85 c0 0f 95 c0 84 c0 0f 84 af 00 00 00 48 8b 05 dd 82 20 00 48 85 c0 74 29 48 8b 05 d1 82 20 00 48 8b 8d 60 ef ff ff 48 8d 95 f0 ef ff ff 48 8d 35 a4 4b 00 00 48 89 c7 b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

