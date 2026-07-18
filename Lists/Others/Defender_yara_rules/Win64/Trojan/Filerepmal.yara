rule Trojan_Win64_Filerepmal_PGFR_2147973696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filerepmal.PGFR!MTB"
        threat_id = "2147973696"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filerepmal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 32 c3 45 32 c8 0f b6 c8 41 80 f1 ?? 49 8b c6 25 ?? ?? ?? ?? 41 c0 c9 05 44 32 0c 11 33 d2 44 32 0c 38 49 8d 46 02 49 f7 f7 48 8b 45 ?? 44 02 0c 16 45 02 cb 45 30 0c 06 4c 8b f3 48 3b 5d 6f 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

