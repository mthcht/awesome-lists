rule Trojan_Win64_Helcobtik_A_2147946168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Helcobtik.A"
        threat_id = "2147946168"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Helcobtik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 a9 74 64 cf [0-16] c1 ea 06 6b c2 4f}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 a9 74 64 cf [0-16] 66 83 e1 7f 66 89 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

