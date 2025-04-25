rule Trojan_Win64_Lrodpmal_A_2147939958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lrodpmal.A"
        threat_id = "2147939958"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lrodpmal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 01 89 4d ?? 8b 55 ?? 83 c2 04 89 55}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 64 8b 11 03 55 08 8b 45 64 89 10 eb}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 6c 8b 48 2c 8b 55 60 66 0f be 04 11 8b 4d 60 8b 55 48 66 89 04 4a 8b 45 60 83 c0 01 89 45 60 eb cc}  //weight: 1, accuracy: High
        $x_1_4 = "Pluprouldeeg.orlo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

