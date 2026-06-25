rule Ransom_Win64_Tedy_VDC_2147972367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Tedy.VDC!MTB"
        threat_id = "2147972367"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files are encrypted" ascii //weight: 1
        $x_2_2 = "dogsomware.pdb" ascii //weight: 2
        $x_2_3 = "locked" wide //weight: 2
        $x_1_4 = "CryptAcquireContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

