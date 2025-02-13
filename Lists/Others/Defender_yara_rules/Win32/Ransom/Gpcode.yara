rule Ransom_Win32_Gpcode_G_2147607918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gpcode.G"
        threat_id = "2147607918"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gpcode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 c0 74 0f 09 d2 74 0b d3 c9 41 31 08 83 c0 04 4a 75 f5 c3}  //weight: 1, accuracy: High
        $x_2_2 = {c7 01 5f 47 5f 50 c7 41 04 5f 43 5f 00 68 ?? ?? ?? ?? 6a 00 68 01 00 1f 00 e8 ?? ?? ?? ?? 09 c0 0f 85 ?? 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {89 c1 81 e1 00 00 00 80 75 55 86 e0 66 3d 01 05 72 25}  //weight: 1, accuracy: High
        $x_1_4 = {0f 31 25 ff 00 00 00 c0 e8 06 74 0b 83 05 ?? ?? ?? 00 14 fe c8 75 f5}  //weight: 1, accuracy: Low
        $x_1_5 = "CryptImportKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

