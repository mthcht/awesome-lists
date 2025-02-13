rule Trojan_Win64_Cigril_D_2147846487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cigril.D!dha"
        threat_id = "2147846487"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cigril"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c4 48 89 84 24 20 01 00 00 8d 42 f0 4d 8b f8 a9 e7 ff ff ff 0f 85 ?? ?? 00 00 83 fa 28 0f 84 ?? ?? 00 00 49 89 5b 08 8d 5a 03 c1 eb 02}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 ec 00 48 b8 00 00 00 00 00 00 00 00 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

