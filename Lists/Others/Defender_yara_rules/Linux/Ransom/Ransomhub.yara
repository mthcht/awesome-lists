rule Ransom_Linux_Ransomhub_A_2147910974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Ransomhub.A"
        threat_id = "2147910974"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Ransomhub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "please wait for the single file encryption to complete" ascii //weight: 1
        $x_1_2 = "unable to encrypt file %s, the file may be empty" ascii //weight: 1
        $x_1_3 = "missing value for -pass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Ransomhub_D_2147922788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Ransomhub.D"
        threat_id = "2147922788"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Ransomhub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 6f 74 65 46 69 6c 65 4e 61 6d 65 15 6a 73 6f 6e 3a 22 6e 6f 74 65 5f 66 69 6c 65 5f 6e 61 6d 65 22 03 0c 4e 6f 74 65 46 75 6c 6c 54 65 78 74}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 6c 66 44 65 6c 65 74 65 12 6a 73 ?? 6e 3a 22 73 65 6c 66 5f 64 65 6c 65 74 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = "*main.BuildConfig" ascii //weight: 1
        $x_1_4 = {57 68 69 74 65 46 6f 6c 64 65 72 73 14 6a 73 6f 6e 3a 22 77 68 69 74 65 5f 66 6f 6c 64 65 72 73 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Ransomhub_E6_2147926022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Ransomhub.E6"
        threat_id = "2147926022"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Ransomhub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "amd64 -fast -pass e685f9e5430ca23488b038991f023864fcb4a599dfbced95dff2ab4b4ded544a -path /" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

