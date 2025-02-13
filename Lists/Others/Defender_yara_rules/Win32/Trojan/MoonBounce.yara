rule Trojan_Win32_MoonBounce_A_2147811488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MoonBounce.A"
        threat_id = "2147811488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MoonBounce"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 03 f0 68 00 20 00 00 ff 76 50 ff 76 34 ff 57 08}  //weight: 1, accuracy: High
        $x_1_2 = {6a 04 68 00 20 00 00 ff 76 50 50 ff 57 08}  //weight: 1, accuracy: High
        $x_1_3 = {f7 ff 83 c7 71 6a 07 8d 04 88 8b d0 83 e2 07 c1 e8 03 0f b6 84 30 c8 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8d 86 e0 01 00 00 50 8d 86 c0 01 00 00 50 8d 86 80 01 00 00 50 8d 86 1c 01 00 00 50 56 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_MoonBounce_B_2147811490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MoonBounce.B!!MoonBounce.B"
        threat_id = "2147811490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MoonBounce"
        severity = "Critical"
        info = "MoonBounce: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 03 f0 68 00 20 00 00 ff 76 50 ff 76 34 ff 57 08}  //weight: 1, accuracy: High
        $x_1_2 = {6a 04 68 00 20 00 00 ff 76 50 50 ff 57 08}  //weight: 1, accuracy: High
        $x_1_3 = {f7 ff 83 c7 71 6a 07 8d 04 88 8b d0 83 e2 07 c1 e8 03 0f b6 84 30 c8 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8d 86 e0 01 00 00 50 8d 86 c0 01 00 00 50 8d 86 80 01 00 00 50 8d 86 1c 01 00 00 50 56 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

