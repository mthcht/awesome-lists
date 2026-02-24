rule Backdoor_Win64_ValleyRAT_GMH_2147963603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ValleyRAT.GMH!MTB"
        threat_id = "2147963603"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 b8 cd cc cc cc 41 f7 e1 80 c1 ?? 49 8d 43 ?? 43 30 4c 10 ?? 45 33 db c1 ea 03 8d 0c 92 03 c9 44 3b c9 4c 0f 45 d8 41 ff c1 44 3b cb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

