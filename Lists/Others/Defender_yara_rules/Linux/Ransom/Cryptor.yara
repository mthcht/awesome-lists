rule Ransom_Linux_Cryptor_B_2147761854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Cryptor.B!MTB"
        threat_id = "2147761854"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Cryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.encrypt" ascii //weight: 2
        $x_2_2 = "qnap_crypt_worker" ascii //weight: 2
        $x_1_3 = "Ch0raix" ascii //weight: 1
        $x_1_4 = "All your data has been locked(crypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_Cryptor_C_2147763660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Cryptor.C!MTB"
        threat_id = "2147763660"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Cryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = ".encrypted" ascii //weight: 2
        $x_2_2 = {2e 2f 72 65 61 64 6d 65 [0-5] 2e 63 72 79 70 74 6f}  //weight: 2, accuracy: Low
        $x_1_3 = "./index.crypto" ascii //weight: 1
        $x_1_4 = "Start encrypting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_Cryptor_D_2147911822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Cryptor.D!MTB"
        threat_id = "2147911822"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Cryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/path/to/be/encrypted" ascii //weight: 1
        $x_1_2 = "/.bash_history" ascii //weight: 1
        $x_1_3 = ".crYpt" ascii //weight: 1
        $x_1_4 = "readme_for_unlock.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Cryptor_E_2147942304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Cryptor.E!MTB"
        threat_id = "2147942304"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Cryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.saveCurrPID" ascii //weight: 1
        $x_1_2 = "main.removeCron" ascii //weight: 1
        $x_1_3 = "main.checkReadmeExists" ascii //weight: 1
        $x_1_4 = "main.writemessage" ascii //weight: 1
        $x_1_5 = "/src/rct_cryptor_universal/main.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

