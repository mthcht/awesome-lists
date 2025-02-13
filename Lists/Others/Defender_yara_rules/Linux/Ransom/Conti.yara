rule Ransom_Linux_Conti_A_2147819084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Conti.A"
        threat_id = "2147819084"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Conti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MIICCAKCAgEA9fA3uvMsSBV0pWu9fVYNc8zXHBe5mADaJ59deeccaCBAgY5T" ascii //weight: 2
        $x_1_2 = "--vmkiller" ascii //weight: 1
        $x_1_3 = "--prockiller" ascii //weight: 1
        $x_1_4 = "paremeter --size cannot be %d" ascii //weight: 1
        $x_2_5 = "All of your files are currently encrypted by CONTI strain" ascii //weight: 2
        $x_1_6 = {48 8b 85 68 ff ff ff 48 8b 48 08 48 ba 0b d7 a3 70 3d 0a d7 a3 48 89 c8 48 f7 ea 48 8d 04 0a 48 89 c2 48 c1 fa 06 48 89 c8 48 c1 f8 3f 48 89 d1 48 29 c1 48 89 c8 48 01 c0 48 89 45 a8 48 8b 85 68 ff ff ff 48 8b 48 08 48 ba 0b d7 a3 70 3d 0a d7 a3 48 89 c8 48 f7 ea 48 8d 04 0a 48 89 c2 48 c1 fa 06 48 89 c8 48 c1 f8 3f 48 29 c2 48 89 d0 48 c1 e0 03 48 01 d0 48 01 c0 48 89 45 b0 e9 ae 03 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {48 8b 85 68 ff ff ff 48 8b 48 08 48 ba 0b d7 a3 70 3d 0a d7 a3 48 89 c8 48 f7 ea 48 8d 04 0a 48 89 c2 48 c1 fa 06 48 89 c8 48 c1 f8 3f 48 29 c2 48 89 d0 48 c1 e0 02 48 01 d0 48 01 c0 48 89 45 a8 48 8b 85 68 ff ff ff 48 8b 48 08 48 ba 0b d7 a3 70 3d 0a d7 a3 48 89 c8 48 f7 ea 48 8d 04 0a 48 89 c2 48 c1 fa 06 48 89 c8 48 c1 f8 3f 48 29 c2 48 89 d0 48 c1 e0 02 48 01 d0 48 01 c0 48 89 45 b0 eb 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_Conti_B_2147888248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Conti.B!MTB"
        threat_id = "2147888248"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c2 48 8d 05 df 17 00 00 48 89 c6 48 89 d7 e8 af e8 ff ff 48 89 45 e8 48 83 7d e8 00 74 2c 48 8b 45 e8 48 89 c1 ba af 0f 00 00 be 01 00 00 00 48 8d 05 ac 07 00 00 48 89 c7 e8 24 e9 ff ff 48 8b 45 e8 48 89 c7}  //weight: 1, accuracy: High
        $x_1_2 = "Entrando a ruta: %s" ascii //weight: 1
        $x_1_3 = "--Iniciando Encriptacion--" ascii //weight: 1
        $x_1_4 = {55 48 89 e5 89 7d ec 89 75 e8 8b 45 ec 99 f7 7d e8 89 55 fc 83 7d fc 00 75 05 8b 45 e8 eb 0e 8b 45 e8 89 45 ec 8b 45 fc 89 45 e8 eb dd 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Conti_C_2147904439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Conti.C!MTB"
        threat_id = "2147904439"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 c0 0f 84 14 01 00 00 48 8d 05 4f 24 00 00 48 89 c7 b8 00 00 00 00 e8 0a ed ff ff b8 00 00 00 00 e9 e3 e9 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "Starting encryption - CONTI POC" ascii //weight: 1
        $x_1_3 = "All of your files are currently encrypted by CONTI strain" ascii //weight: 1
        $x_1_4 = "The ransomware won't encrypt anything without it" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Conti_D_2147905006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Conti.D!MTB"
        threat_id = "2147905006"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".conti" ascii //weight: 1
        $x_1_2 = "./locker --path /path" ascii //weight: 1
        $x_1_3 = "InitializeEncryptor" ascii //weight: 1
        $x_1_4 = "CONTI_README.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

