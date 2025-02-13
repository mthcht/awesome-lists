rule Trojan_Win64_ValleyRat_ASD_2147929877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.ASD!MTB"
        threat_id = "2147929877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {2b c8 b8 cd cc cc cc 41 f7 e2 80 c1 36 49 8d 43 01 41 30 4c 38 ff 45 33 db c1 ea 03 41 ff c2 8d 0c 92 03 c9 44 3b c9 4c 0f 45 d8}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

