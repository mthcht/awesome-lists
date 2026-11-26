rule Trojan_Win64_Zincask_AA_2147982843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zincask.AA!MTB"
        threat_id = "2147982843"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zincask"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 01 e9 4c 01 ca 48 89 d6 48 c1 ee ?? 48 31 d6 49 0f af f4 49 89 f1 49 c1 e9 ?? 4c 33 ce c1 e1 ?? 49 8b f1 48 d3 ee 41 30 32 31 c9}  //weight: 10, accuracy: Low
        $x_2_2 = {44 89 d6 45 8b 13 44 3b d6 73 ?? 49 ff c1 49 83 c3 ?? 4c 3b ca 75}  //weight: 2, accuracy: Low
        $x_8_3 = {4d 89 ce 49 c1 ee ?? 4d 89 f7 4b 8d 04 f6 4c 8d 24 40 49 c1 e7 ?? 4d 03 e6 48 89 f9 4d 89 f1 4e 8d 04 27 4a 8d 14 3f}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

