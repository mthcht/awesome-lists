rule Trojan_Win32_Kuluoz_A_2147655628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kuluoz.gen!A"
        threat_id = "2147655628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuluoz"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "^[a-zA-Z]:.*\\\\(.*)$" ascii //weight: 2
        $x_1_2 = {83 c4 0c 81 bc 24 ?? ?? 00 00 00 00 20 03 0f 8d ?? ?? 00 00 8d 84 24 ?? ?? 00 00 e8 ?? ?? ?? ?? 03 84 24 ?? ?? 00 00 3d 00 00 20 03 0f 86}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 18 81 bd ?? ?? ff ff 00 00 20 03 0f 8d ?? ?? 00 00 8b 85 ?? ?? ff ff 8a c8 f6 d1 80 e1 01 88 8d ?? ?? ff ff 0f 85 ?? ?? 00 00 8b 8d ?? ?? ff ff 85 c9 0f 84 ?? ?? 00 00 c1 e8 02 a8 01 74 ?? 8b 11 8b 42 34 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kuluoz_B_2147657317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kuluoz.gen!B"
        threat_id = "2147657317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuluoz"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 70 68 70 3f 72 3d 67 61 74 65 2f 64 63 68 65 63 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {56 6a f1 50 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 68 10 27 00 00 ff d6 eb f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

