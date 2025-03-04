rule Ransom_Win64_CONTI_DB_2147770353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CONTI.DB!MTB"
        threat_id = "2147770353"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CONTI"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "all of the data that has been encrypted" ascii //weight: 1
        $x_1_2 = "https://contirecovery.info" ascii //weight: 1
        $x_1_3 = "cryptor_dll.pdb" ascii //weight: 1
        $x_1_4 = "YOU SHOULD BE AWARE!" ascii //weight: 1
        $x_1_5 = ".onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

