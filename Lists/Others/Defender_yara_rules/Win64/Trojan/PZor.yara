rule Trojan_Win64_PZor_A_2147843176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PZor.A!MTB"
        threat_id = "2147843176"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PZor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 ea 4c 01 e2 4d 89 fa 49 c1 ea ?? 4d 89 f3 49 c1 eb 10 49 b8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

