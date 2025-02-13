rule Ransom_MSIL_ColdLocker_DA_2147765425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ColdLocker.DA!MTB"
        threat_id = "2147765425"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ColdLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ColdLocker" ascii //weight: 1
        $x_1_2 = "How To Unlock Files.txt" ascii //weight: 1
        $x_1_3 = "readme.tmp" ascii //weight: 1
        $x_1_4 = "\\ColdLocker\\obj\\Release\\ColdLocker.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

