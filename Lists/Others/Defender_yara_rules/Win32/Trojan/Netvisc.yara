rule Trojan_Win32_Netvisc_A_2147653530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netvisc.A"
        threat_id = "2147653530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netvisc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 53 4f 43 4b 5f 63 6f 6e 6e 65 63 74 20 4f 4b 21 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 6d 79 66 77 2e 75 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {c6 85 60 df ff ff 2f c6 85 61 df ff ff 54 c6 85 62 df ff ff 41 c6 85 63 df ff ff 53 c6 85 64 df ff ff 4b c6 85 65 df ff ff 4b c6 85 66 df ff ff 49 c6 85 67 df ff ff 4c c6 85 68 df ff ff 4c}  //weight: 1, accuracy: High
        $x_1_4 = {53 56 57 c6 85 ?? ?? ?? ?? 55 c6 85 ?? ?? ?? ?? 4e c6 85 ?? ?? ?? ?? 4b c6 85 ?? ?? ?? ?? 4e c6 85 ?? ?? ?? ?? 4f c6 85 ?? ?? ?? ?? 57 c6 85 ?? ?? ?? ?? 4e c6 85 ?? ?? ?? ?? 20}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 44 24 04 54 c6 44 24 05 6e c6 44 24 06 65 c6 44 24 07 74 c6 44 24 08 73 c6 44 24 09 76 c6 44 24 0a 63 88 44 24 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

