rule Trojan_Win64_FaceLight_B_2147932407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FaceLight.B!dha"
        threat_id = "2147932407"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FaceLight"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c9 ba 00 00 a0 00 41 b8 00 10 00 00 44 8d 49 04 48 89}  //weight: 5, accuracy: High
        $x_5_2 = {33 d2 41 b8 00 00 a0 00 48 8b c8 48 8b f8 e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

