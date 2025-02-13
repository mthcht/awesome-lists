rule Ransom_Linux_Defray_A_2147767622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Defray.A!MTB"
        threat_id = "2147767622"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Defray"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NEWS_FOR_EIGSI!.txt" ascii //weight: 1
        $x_1_2 = "france.eigs@protonmail.com" ascii //weight: 1
        $x_1_3 = "You can mail us one crypted document" ascii //weight: 1
        $x_1_4 = "CHANGING content or names of crypted files (*.31gs1)" ascii //weight: 1
        $x_1_5 = "g_RansomHeader" ascii //weight: 1
        $x_1_6 = "ransomware.c" ascii //weight: 1
        $x_1_7 = "ReadMeStoreForDir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

