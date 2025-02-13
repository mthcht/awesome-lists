rule Trojan_Win64_VibrantPony_A_2147919754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VibrantPony.A!dha"
        threat_id = "2147919754"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VibrantPony"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 bc 00 30 00 00 41 b9 04 00 00 00 ba 00 28 00 00 33 c9 45 8b c4 48 89 45 ?? ff d7}  //weight: 5, accuracy: Low
        $x_5_2 = {49 63 46 3c 44 0f be 4d af 45 8b c4 42 8b 54 30 50 41 c1 e1 03 33 c9 ff d7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VibrantPony_C_2147920292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VibrantPony.C"
        threat_id = "2147920292"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VibrantPony"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 01 03 c6 48 03 ce 83 f8 6a 72}  //weight: 1, accuracy: High
        $x_1_2 = {41 8b c5 48 8d ?? ?? 88 01 03 c6 48 03 ce 83 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_VibrantPony_B_2147920293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VibrantPony.B"
        threat_id = "2147920293"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VibrantPony"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 64 00 c7 45 ?? ?? 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 0c 09 3d 00 41 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

