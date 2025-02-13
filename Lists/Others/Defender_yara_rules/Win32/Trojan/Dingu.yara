rule Trojan_Win32_Dingu_A_2147633325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dingu.A"
        threat_id = "2147633325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dingu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 05 80 3e 2e 75 05 8a 16 88 17 47 8a 46 01 46 84 c0 75}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 37 8a c8 8a d0 80 e1 0c c0 e2 04 0a ca 8a d0 c0 fa 02 c0 e1 02 80 e2 0c c0 f8 06 0a ca 24 03 0a c8 88 0e 46 4d 75 d7}  //weight: 1, accuracy: High
        $x_1_3 = {b9 58 00 00 00 33 c0 bf ?? ?? ?? ?? f3 ab a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 70 00 00 3b ?? 0f 84}  //weight: 1, accuracy: Low
        $x_1_4 = {7e 14 8b 4c 24 04 53 8a 1c 08 80 f3 ?? 88 1c 08 40 3b c2 7c f2}  //weight: 1, accuracy: Low
        $x_1_5 = {bf 01 00 00 00 a0 ?? ?? ?? ?? 32 db 84 c0 75 ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 68 e8 03 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {83 f8 02 0f 82 ?? ?? 00 00 83 f8 04 0f 87 ?? ?? 00 00 83 f8 03 75 ?? 89 06}  //weight: 1, accuracy: Low
        $x_1_7 = "VERSION3.2 with Encrypted " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

