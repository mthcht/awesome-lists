rule Ransom_Linux_BabukCrypt_PA_2147786328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/BabukCrypt.PA!MTB"
        threat_id = "2147786328"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "BabukCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".babyk" ascii //weight: 1
        $x_1_2 = "/How To Restore Your Files.txt" ascii //weight: 1
        $x_1_3 = "/path/to/be/encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_BabukCrypt_PB_2147787446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/BabukCrypt.PB!MTB"
        threat_id = "2147787446"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "BabukCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encrypt" ascii //weight: 1
        $x_1_2 = "filepath.Walk" ascii //weight: 1
        $x_1_3 = "crypto/chacha20" ascii //weight: 1
        $x_1_4 = "BABUK_LOCK_curve25519" ascii //weight: 1
        $x_1_5 = "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

