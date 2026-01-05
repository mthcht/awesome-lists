rule Ransom_Win32_Goransom_MKA_2147960529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Goransom.MKA!MTB"
        threat_id = "2147960529"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Goransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6FKraiyt_wLgc6guBoJs/T6k90G4H9FAtoaJKZFkx/72OZO2dvXaeN9z-fo8NS/xSVqfqiL0ac5w2RPhnWA" ascii //weight: 1
        $x_1_2 = "Encrypt" ascii //weight: 1
        $x_1_3 = "aes.encryptBlockGo" ascii //weight: 1
        $x_1_4 = "Encrypt.stkobj" ascii //weight: 1
        $x_5_5 = "goransom/utils.Encrypt" ascii //weight: 5
        $x_1_6 = "cipher.NewCFBDecrypter" ascii //weight: 1
        $x_5_7 = "goransom.go" ascii //weight: 5
        $x_5_8 = "main.ransomware" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Goransom_MKB_2147960530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Goransom.MKB!MTB"
        threat_id = "2147960530"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Goransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qp9Xe0v8Zzt9IwBj9_Wt/tilZJP1eGWylLw-kTJuw/Bqr7IIku6bame9non3UZ/fLk4axx9eYm_wDu6J7Xk" ascii //weight: 1
        $x_1_2 = "main.encrypt" ascii //weight: 1
        $x_1_3 = "aes.encryptBlockGo" ascii //weight: 1
        $x_1_4 = "des.encryptBlock" ascii //weight: 1
        $x_1_5 = "XORKeyStream" ascii //weight: 1
        $x_5_6 = "PublicKey" ascii //weight: 5
        $x_5_7 = "goransom.go" ascii //weight: 5
        $x_1_8 = "Lock" ascii //weight: 1
        $x_1_9 = "main.func" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

