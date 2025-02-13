rule Ransom_Linux_FastCrypt_A_2147915883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/FastCrypt.A!MTB"
        threat_id = "2147915883"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "FastCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.PasteRansomNote" ascii //weight: 1
        $x_1_2 = "FastCryptFiles" ascii //weight: 1
        $x_1_3 = "main.CryptAllDisk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

