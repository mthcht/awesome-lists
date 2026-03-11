rule Ransom_Linux_GunraCrypt_PB_2147964555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/GunraCrypt.PB!MTB"
        threat_id = "2147964555"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "GunraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Your data has been encrypted" ascii //weight: 4
        $x_1_2 = "R3ADM3.txt" ascii //weight: 1
        $x_1_3 = "%s/%s.keystore" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

