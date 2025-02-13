rule Ransom_Linux_KMDLocker_A_2147847299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/KMDLocker.A!MTB"
        threat_id = "2147847299"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "KMDLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encrypt.func" ascii //weight: 1
        $x_1_2 = "main.create_message" ascii //weight: 1
        $x_1_3 = "/opt/agelocker/agelocker.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

