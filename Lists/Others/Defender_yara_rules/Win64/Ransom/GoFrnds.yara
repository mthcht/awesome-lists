rule Ransom_Win64_GoFrnds_YAR_2147913435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GoFrnds.YAR!MTB"
        threat_id = "2147913435"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GoFrnds"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 8b 4c 24 4c 41 8d b1 65 78 70 61 33 70 20 c1 c6 10 8b 7c 24 3c 01 f7 89 7c 24 70 44 31 cf c1 c7 0c 45 8d 14 39 46 8d 0c 0f 45 8d 89 65 78 70 61 41 31 f1}  //weight: 10, accuracy: High
        $x_10_2 = "Go build ID:" ascii //weight: 10
        $x_1_3 = "3-P8HXdP5lWesLeithgX/ViSEejkW7bn08eE7Ljkc/fd_CK8fC_Rx0KUVgUE4u/88Ax6Vg-ys90dKV5qmY_" ascii //weight: 1
        $x_10_4 = ".frnds" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

