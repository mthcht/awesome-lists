rule Ransom_Win64_Sinobi_YAC_2147946137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Sinobi.YAC!MTB"
        threat_id = "2147946137"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Sinobi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--encrypt-network" ascii //weight: 1
        $x_1_2 = "--no-background" ascii //weight: 1
        $x_1_3 = "Encrypt only specified directory" ascii //weight: 1
        $x_1_4 = "Load hidden drives " ascii //weight: 1
        $x_1_5 = "Encryption mode" ascii //weight: 1
        $x_10_6 = "Enable silent encryption (no extension and notes will be added)" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

