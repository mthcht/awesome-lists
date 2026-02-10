rule Trojan_Win64_DarkSideRat_ADS_2147962752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkSideRat.ADS!MTB"
        threat_id = "2147962752"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkSideRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 bf 3c b6 22 f7 e9 c1 fa 03 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 3b 0f b6 c1 2a c2 04 3a 32 07 34 37 88 07 ff c1 48 8d 7f 01 83 f9 32}  //weight: 2, accuracy: High
        $x_1_2 = {48 8b f0 8b 05 ?? 3e 00 00 89 44 24 30 0f b6 05 ?? 3e 00 00 c6 44 24 30 2e 80 74 24 31 0c 80 74 24 32 0b 80 74 24 33 0a 34 09 88 44 24 34 48 8d 44 24 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

