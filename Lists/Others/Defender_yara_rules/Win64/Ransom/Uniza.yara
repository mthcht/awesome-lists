rule Ransom_Win64_Uniza_PA_2147845440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Uniza.PA!MTB"
        threat_id = "2147845440"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Uniza"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UNIZA RANSOMWARE" ascii //weight: 1
        $x_1_2 = "All your files were encrypted" ascii //weight: 1
        $x_1_3 = "advanced cryptographic technology" ascii //weight: 1
        $x_1_4 = "pay the ransom and DM me" ascii //weight: 1
        $x_1_5 = "Release\\Rans.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

