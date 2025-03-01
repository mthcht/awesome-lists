rule Ransom_Linux_GonnaCry_A_2147795814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/GonnaCry.A!MTB"
        threat_id = "2147795814"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "GonnaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Sup brother, all your files below have been encrypted, cheers!" ascii //weight: 2
        $x_1_2 = "KEY = %s IV = %s PATH = %s" ascii //weight: 1
        $x_1_3 = "/home/tarcisio/tests/" ascii //weight: 1
        $x_1_4 = "zip backup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_GonnaCry_B_2147796723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/GonnaCry.B!MTB"
        threat_id = "2147796723"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "GonnaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gona to delete file %s" ascii //weight: 1
        $x_1_2 = "rsa_crpt.c" ascii //weight: 1
        $x_1_3 = "/tmp/GNNCRY_Readme.txt!" ascii //weight: 1
        $x_1_4 = "we have done encrypt!" ascii //weight: 1
        $x_1_5 = "decrypt all file ,ssid:%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_GonnaCry_D_2147931052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/GonnaCry.D!MTB"
        threat_id = "2147931052"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "GonnaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gonnacry" ascii //weight: 1
        $x_1_2 = "enc_files.gc" ascii //weight: 1
        $x_1_3 = "home/tarcisio/test" ascii //weight: 1
        $x_1_4 = "your_encrypted_files.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_GonnaCry_E_2147932633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/GonnaCry.E!MTB"
        threat_id = "2147932633"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "GonnaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 1e fa 55 48 89 e5 53 48 81 ec 68 05 00 00 48 89 bd 98 fa ff ff 64 48 8b 04 25 28 00 00 00 48 89 45 e8 31 c0 48 8d 85 b0 fa ff ff 48 89 85 a0 fa ff ff 48 8d 05 cd 3d 01 00 48 89 85 a8 fa ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 85 a8 fa ff ff 48 83 c0 01 48 89 85 a8 fa ff ff 48 8b 85 a0 fa ff ff 48 8b 10 48 8b 85 a0 fa ff ff 48 83 e8 08 48 8b 00 48 39 c2 0f 95 c1 48 8b 85 a0 fa ff ff 48 8d 50 f8 0f b6 c1 89 02 48 8b 85 a0 fa ff ff 48 83 e8 08 48 89 85 a0 fa ff ff e9 bf 12 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

