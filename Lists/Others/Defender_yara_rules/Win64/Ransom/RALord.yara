rule Ransom_Win64_RALord_BB_2147939224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/RALord.BB!MTB"
        threat_id = "2147939224"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "RALord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RALord ransomware" ascii //weight: 1
        $x_1_2 = ".onion" ascii //weight: 1
        $x_1_3 = "please do not touch the files becouse we can't decrypt it if you touch it" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

