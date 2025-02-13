rule Trojan_Win64_Raccoon_DB_2147846895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Raccoon.DB!MTB"
        threat_id = "2147846895"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 d0 05 4f d4 a4 db 35 be 98 68 c9 c1 c0 f6 66 9d e9 [0-4] 41 0f b6 04 08 88 01 48 8d 49 01 48 83 ea 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Raccoon_CBVV_2147851987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Raccoon.CBVV!MTB"
        threat_id = "2147851987"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 48 98 0f b6 44 04 70 48 63 4c 24 2c 48 8b 94 24 ?? ?? ?? ?? 0f b6 0c 0a 33 c8 8b c1 48 63 4c 24 2c 48 8b 94 24 ?? ?? ?? ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

