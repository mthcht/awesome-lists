rule Trojan_Win32_GreenBug_A_2147727216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GreenBug.A"
        threat_id = "2147727216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GreenBug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 10 f8 dd 00 83 c0 01 a3 10 f8 dd 00 83 3d 10 f8 dd 00 40 75 0a c7 05 10 f8 dd 00 00 00 00 00 8b 0d 10 f8 dd 00 69 c9 2c 01 00 00 8a 55 08 88 91 2c 64 d9 00 a1 10 f8 dd 00 69 c0 2c 01 00 00 c6 80 2d 64 d9 00 00 a1 10 f8 dd 00 69 c0 2c 01 00 00 05 2c 64 d9 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 04 50 6a ?? e8 20 ?? ?? ?? 83 c4 04 50 6a ?? e8 15 ?? ?? ?? 83 c4 04 50 6a ?? e8 0a ?? ?? ?? 83 c4 04 50 6a ?? e8 ff ?? ?? ?? 83 c4 04 50 6a ?? e8 f4 ?? ?? ?? 83 c4 04 50 6a ?? e8 e9}  //weight: 1, accuracy: Low
        $x_1_3 = "Turn off the television as it is only a flashing box distraction from life! Interact" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

