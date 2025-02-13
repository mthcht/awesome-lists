rule Ransom_Linux_Akita_A_2147918842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Akita.A!MTB"
        threat_id = "2147918842"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Akita"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AkitaCrypt" ascii //weight: 1
        $x_1_2 = "./encrypt [key]" ascii //weight: 1
        $x_1_3 = "/root/decrypt.html" ascii //weight: 1
        $x_1_4 = "getmyfilesbacknow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

