rule Trojan_Win64_MimiKatz_STA_2147775989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MimiKatz.STA"
        threat_id = "2147775989"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MimiKatz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b8 00 00 00 00 00 00 00 00 48 ?? ?? ?? ?? 48 ff c0 e9 ?? ?? 00 00 48 8b 40 18 ff f0 8f ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 c0 00 00 00 00 81 c0 00 00 00 00 81 c0 00 00 00 00 81 c0 00 00 00 00 81 c0 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 48 81 c4 ?? ?? ?? ?? 48 81 c4 ?? ?? ?? ?? 48 81 c4 ?? ?? ?? ?? 48 81 c4 ?? ?? ?? ?? 48 81 c4}  //weight: 1, accuracy: Low
        $x_10_4 = {ff 74 24 08 8f c1 c6 04 01}  //weight: 10, accuracy: High
        $x_10_5 = {48 03 4c 24 08 c6 04 01}  //weight: 10, accuracy: High
        $x_10_6 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 50 00 75 00 54 00 54 00 59 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

