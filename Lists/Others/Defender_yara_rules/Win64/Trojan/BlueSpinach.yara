rule Trojan_Win64_BlueSpinach_A_2147949716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlueSpinach.A"
        threat_id = "2147949716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlueSpinach"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 20 41 8b d9 49 8b f8 48 8b f2 48 8b e9 e8 4b 00 00 00 48 8b 0d ?? ?? ?? ?? 45 33 c0 ba 01 00 00 00 48 8d 81 ?? ?? ?? ?? ff d0 48 8b 05 ?? ?? ?? ?? 44 8b cb 48 05 ?? ?? ?? ?? 4c 8b c7 48 8b d6 48 8b cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

