rule Ransom_Linux_Lucky_A_2147795815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Lucky.A!MTB"
        threat_id = "2147795815"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Lucky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Some files has crypted" ascii //weight: 1
        $x_1_2 = "if you want your files back , send 1 bitcoin to my wallet" ascii //weight: 1
        $x_1_3 = "/root/How_To_Decrypt_My_File" ascii //weight: 1
        $x_1_4 = "rsa_crpt.c" ascii //weight: 1
        $x_1_5 = "/tmp/Ssession" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

