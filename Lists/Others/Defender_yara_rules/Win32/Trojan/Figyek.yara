rule Trojan_Win32_Figyek_A_2147695285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Figyek.A"
        threat_id = "2147695285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Figyek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bc ff ff 00 00 00 00 eb 0f 8b ?? ?? bc ff ff 83 ?? 01 89 ?? ?? bc ff ff 81 bd ?? bc ff ff ?? ?? ?? ?? 0f 8d ?? 00 00 00 ?? ?? 00 00 00 83 ?? 01 89 ?? ?? bc ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {bc ff ff 81 ?? a8 00 00 00 88 ?? ?? bc ff ff 8b ?? ?? 03 ?? ?? bc ff ff 8a ?? 88 ?? ?? bc ff ff 0f b6 ?? ?? bc ff ff 0f b6 ?? ?? bc ff ff 33 ?? 8b ?? ?? bd ff ff 03 ?? ?? bc ff ff 88}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 83 e9 01 8b 85 ?? ?? ff ff 99 f7 f9 89 95 ?? ?? ff ff 8b 95 ?? ?? ff ff 0f b6 82 00 20 41 00 35 a8 00 00 00 88 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f1 a8 00 00 00 88 8d ?? ?? ff ff 8b 95 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 88 00 20 41 00 81 f1 a8 00 00 00 88 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_6 = {0f b6 88 00 20 41 00 33 d1 8b 85 ?? ?? ff ff 03 85 ?? ?? ff ff 88 10 e9}  //weight: 1, accuracy: Low
        $x_1_7 = {99 b9 d1 00 00 00 f7 f9 89 95 ?? ?? ff ff 8b 55 d0 03 95 ?? ?? ff ff 0f b6 02 8b 8d ?? ?? ff ff 0f b6 91 ?? ?? ?? ?? 33 c2}  //weight: 1, accuracy: Low
        $x_1_8 = {0f b6 02 8b ?? ?? ?? ff ff 0f b6 91 ?? ?? ?? ?? 33 c2 8b 4d ?? 03 ?? ?? ?? ff ff 88 01 (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_9 = {0f b6 02 8b ?? ?? ?? ff ff 0f b6 91 ?? ?? ?? ?? 33 c2 8b ?? ?? ?? ff ff 03 ?? ?? ?? ff ff 88 01 (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_10 = {ff ff 6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 10 68 ?? f1 40 00 ff 95 ?? ff ff ff 89 85 ?? bd ff ff}  //weight: 1, accuracy: Low
        $x_1_11 = {89 45 84 6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 10 68 9c f1 40 00 ff 55 84 89 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_12 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 10 68 b0 f1 40 00 ff 15 ?? ?? ?? ?? 89 85 40 ff ff ff 83 bd 40 ff ff ff ff 0f 84 66 01 00 00 8b}  //weight: 1, accuracy: Low
        $x_1_13 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 10 68 ?? ?? 40 00 ff 15 ?? ?? ?? 00 89 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_14 = {ff 15 08 f0 40 00 89}  //weight: 1, accuracy: High
        $x_1_15 = {ff 15 08 20 41 00 89}  //weight: 1, accuracy: High
        $x_1_16 = {ff 15 08 20 41 00 89 85 60 ff ff ff 8b}  //weight: 1, accuracy: High
        $x_1_17 = {ff 15 08 10 41 00 89 85 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_18 = {ff 15 08 c0 40 00 89 ?? ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_19 = {0b 00 00 83 c4 0c 85 c0 74 ?? c7 45 ?? 6e 00 00 00 68 ?? 12 41 00 8d ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_20 = {f1 40 00 8b 4d ?? e8 ?? ?? 00 00 89 45 ?? 83 7d ?? 00 74 ?? 8b ?? ?? ?? 8b ?? ?? ?? ff 55}  //weight: 1, accuracy: Low
        $x_1_21 = {68 b0 12 41 00 8d 45 ?? 50 e8 ?? 41 00 00}  //weight: 1, accuracy: Low
        $x_1_22 = {0f b6 d0 85 d2 74 ?? 68 90 f1 40 00 8b 4d ?? e8}  //weight: 1, accuracy: Low
        $x_1_23 = {83 c0 01 89 85 ?? ?? ?? ff 81 bd ?? ?? ff ff ?? ?? ?? ?? 7d ?? 8b 85 ?? ?? ff ff 99 b9 ?? 00 00 00 f7 f9 89}  //weight: 1, accuracy: Low
        $x_1_24 = {2e 67 69 66 00 [0-10] 72 75 6e 6d 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

