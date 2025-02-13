rule Ransom_MSIL_SatnEncrypt_PA_2147772983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SatnEncrypt.PA!MTB"
        threat_id = "2147772983"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SatnEncrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".SnakeEye" wide //weight: 1
        $x_1_2 = "SNAKE EYE SQUAD" wide //weight: 1
        $x_1_3 = {5c 53 41 54 41 4e 20 45 4e 43 52 59 50 54 45 44 20 59 4f 55 5c [0-16] 5c [0-16] 5c 53 41 54 41 4e 20 45 4e 43 52 59 50 54 45 44 20 59 4f 55 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_4 = "SATAN ENCRYPTED YOU.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

