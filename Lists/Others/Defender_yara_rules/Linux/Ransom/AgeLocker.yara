rule Ransom_Linux_AgeLocker_A_2147768879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/AgeLocker.A!MTB"
        threat_id = "2147768879"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "AgeLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/opt/agelocker/agelocker.go" ascii //weight: 1
        $x_1_2 = "main.encrypt" ascii //weight: 1
        $x_1_3 = "main.stop_service" ascii //weight: 1
        $x_1_4 = "golang.org/x/crypto/chacha20" ascii //weight: 1
        $x_1_5 = "main.stringInSlice" ascii //weight: 1
        $x_1_6 = "FILES ARE ENCRYPTED." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

