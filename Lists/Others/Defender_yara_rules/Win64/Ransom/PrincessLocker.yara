rule Ransom_Win64_PrincessLocker_CD_2147951706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PrincessLocker.CD!MTB"
        threat_id = "2147951706"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PrincessLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Critical data has been exfiltrated.  " ascii //weight: 5
        $x_5_2 = "Your network infrastructure has been compromised" ascii //weight: 5
        $x_5_3 = "Files have been encrypted" ascii //weight: 5
        $x_5_4 = ".onion/chat" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

