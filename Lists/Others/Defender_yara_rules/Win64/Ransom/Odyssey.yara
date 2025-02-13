rule Ransom_Win64_Odyssey_ARA_2147915412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Odyssey.ARA!MTB"
        threat_id = "2147915412"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Odyssey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Monero Address" ascii //weight: 2
        $x_2_2 = "Hacked By NetX" ascii //weight: 2
        $x_2_3 = "\\RansomWare-encrypt.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

