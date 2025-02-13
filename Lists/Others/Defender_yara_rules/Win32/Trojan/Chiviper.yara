rule Trojan_Win32_Chiviper_C_2147633131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chiviper.C"
        threat_id = "2147633131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chiviper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 08 2a ca 32 ca 88 08 40 4e 75 f4}  //weight: 2, accuracy: High
        $x_2_2 = {8b f0 6a 7c 56 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 0f 84 ?? ?? 00 00 83 c6 06}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 02 6a 00 68 0c fe ff ff 56 ff 15 ?? ?? ?? ?? 68 f4 01 00 00 e8 d6 12 00 00 83 c4 04 8d 54 24 08 8b f8 6a 00 52 68 f4 01 00 00 57 56 ff 15}  //weight: 2, accuracy: Low
        $x_1_4 = "mac=%s&ver=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Chiviper_D_2147633333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chiviper.D"
        threat_id = "2147633333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chiviper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 64 ff d7 a1 ?? ?? ?? ?? 83 f8 03 74 05 83 f8 01 75 ed}  //weight: 1, accuracy: Low
        $x_1_2 = "%s?mac=%s&ver=%s&os=%s" ascii //weight: 1
        $x_1_3 = {77 65 62 73 72 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

