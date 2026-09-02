rule Ransom_Linux_OrovaCrypt_PA_2147977378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/OrovaCrypt.PA!MTB"
        threat_id = "2147977378"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "OrovaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "OROVAENCRYPTED" ascii //weight: 3
        $x_1_2 = "encrypted by OROVA ransomware" ascii //weight: 1
        $x_1_3 = "000___How_to_Recover_Encrypted_Files___000.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

