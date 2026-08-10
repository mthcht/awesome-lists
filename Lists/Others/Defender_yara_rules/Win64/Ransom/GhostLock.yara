rule Ransom_Win64_GhostLock_MKV_2147975835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GhostLock.MKV!MTB"
        threat_id = "2147975835"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "=== GHOSTLOCK RANSOMWARE ===" ascii //weight: 2
        $x_2_2 = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii //weight: 2
        $x_2_3 = "DO NOT attempt to decrypt files yourself!" ascii //weight: 2
        $x_2_4 = "Ransom note deployed:" ascii //weight: 2
        $x_2_5 = ".ghostlocked" ascii //weight: 2
        $x_2_6 = "GHOSTLOCK.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

