rule Ransom_MSIL_Nanocrypt_YAC_2147938647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Nanocrypt.YAC!MTB"
        threat_id = "2147938647"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "is locked" wide //weight: 1
        $x_1_2 = "Access denied to file" wide //weight: 1
        $x_1_3 = "/C reagentc /disable" wide //weight: 1
        $x_1_4 = "README.txt" wide //weight: 1
        $x_1_5 = ".ncrypt" wide //weight: 1
        $x_10_6 = "ENCRYPTED BY NANOCRYPT RANSOMWARE" wide //weight: 10
        $x_1_7 = "payment has been authorized" wide //weight: 1
        $x_1_8 = "decryption key" wide //weight: 1
        $x_1_9 = "boot back into windows" wide //weight: 1
        $x_1_10 = "CREATED FOR FUN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

