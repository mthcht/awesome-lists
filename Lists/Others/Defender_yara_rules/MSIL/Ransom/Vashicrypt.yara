rule Ransom_MSIL_Vashicrypt_A_2147722961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Vashicrypt.A"
        threat_id = "2147722961"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vashicrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Ransomware-master\\Shiva" ascii //weight: 3
        $x_2_2 = "ShivaForm" ascii //weight: 2
        $x_1_3 = "messageCreator" ascii //weight: 1
        $x_1_4 = "selfDestroy" ascii //weight: 1
        $x_1_5 = "startAction" ascii //weight: 1
        $x_1_6 = "EncryptFile" ascii //weight: 1
        $x_1_7 = "encryptDirectory" ascii //weight: 1
        $x_1_8 = "CreateRandomString" ascii //weight: 1
        $x_2_9 = "/C timeout 2 && Del /Q /F" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

