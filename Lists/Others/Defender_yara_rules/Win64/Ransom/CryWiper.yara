rule Ransom_Win64_CryWiper_PA_2147836499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CryWiper.PA!MTB"
        threat_id = "2147836499"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CryWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CRY" ascii //weight: 1
        $x_1_2 = "README.txt" ascii //weight: 1
        $x_1_3 = "All your important files were encrypted" ascii //weight: 1
        $x_1_4 = "vssadmin delete shadows /for=c: /all" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

