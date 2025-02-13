rule Trojan_Win32_Setaclod_A_2147697199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Setaclod.A"
        threat_id = "2147697199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Setaclod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UTEX20-13H2OM-1202" wide //weight: 1
        $x_1_2 = "cqonjbcuhqo.z.vyx,hpqo.ttmdpdnffc" wide //weight: 1
        $x_1_3 = {8d 54 24 10 52 ff d3 83 f8 03 74 05 83 f8 02 75 0e 8b 4c 24 0c 8d 44 24 10 50 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 47 83 c6 04 8d 50 02 66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 3b f8 7c}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 56 55 55 55 f7 ee 8b c2 c1 e8 1f 03 c2 8d 14 40 8b c6 2b c2 75 08 ba ff ff 00 00 66 01 11 83 f8 01 75 04 66 83 01 03 83 f8 02 75 03 66 01 01 83 c1 02 46 66 83 39 00 75 c6 5e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

