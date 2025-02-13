rule Ransom_Linux_ItsSoEasy_A_2147847735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/ItsSoEasy.A!MTB"
        threat_id = "2147847735"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "ItsSoEasy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "actFile encryptData" ascii //weight: 1
        $x_1_2 = "/itssoeasy.html" ascii //weight: 1
        $x_1_3 = "encryptedFileDB" ascii //weight: 1
        $x_1_4 = "identFile removeAllFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

