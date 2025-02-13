rule Ransom_Win64_TeslaCrypt_AB_2147907453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/TeslaCrypt.AB!MTB"
        threat_id = "2147907453"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "TeslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "V:\\geritjei\\adkmgrjgii\\dfe\\wfef.pdb" ascii //weight: 10
        $x_1_2 = "CoInternetCreateZoneManager" ascii //weight: 1
        $x_1_3 = "SetupDiGetActualSectionToInstallA" ascii //weight: 1
        $x_1_4 = "FindNextVolumeMountPointA" ascii //weight: 1
        $x_1_5 = "CreateTapePartition" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

