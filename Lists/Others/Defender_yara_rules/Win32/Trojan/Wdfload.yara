rule Trojan_Win32_Wdfload_A_2147722011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wdfload.A!bit"
        threat_id = "2147722011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wdfload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 08 8b 44 24 08 80 ?? ?? 8a [0-6] 32 c8 8b 44 24 08 88 [0-6] ff 44 24 08 83 7c 24 08 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 08 8d 52 01 ?? ?? 81 c6 ?? ?? ?? ?? 88 8d ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 30 42 ff 8b 85 ?? ?? ?? ?? 83 ef 01 75 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

