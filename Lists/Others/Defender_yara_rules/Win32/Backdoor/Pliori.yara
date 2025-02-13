rule Backdoor_Win32_Pliori_A_2147626475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pliori.A"
        threat_id = "2147626475"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pliori"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 89 3e 8b d6 83 c2 05 8b c3 e8 ?? ?? ?? 00 8b d6 83 c2 04 88 02 c6 03 e9 47 8b 45 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04 75 c5}  //weight: 1, accuracy: High
        $x_1_3 = {b8 20 4e 00 00 e8 ?? ?? ?? ff e8 ?? ?? ?? ff 8d 45 fc e8 ?? ?? ?? ff 8d 45 fc 50 8d 4d f8 66 ba d2 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

