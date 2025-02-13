rule Ransom_Win32_Fargo_ZZ_2147837187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Fargo.ZZ"
        threat_id = "2147837187"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Fargo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {53 56 57 ff 15 ?? ?? ?? ?? 0f b7 c0 b9 19 04 00 00 66 3b c1 0f 84 ?? ?? ?? ?? 83 c1 26 66 3b c1 0f 84 ?? ?? ?? ?? b9 23 04 00 00 66 3b c1 0f 84 ?? ?? ?? ?? 49 66 3b c1 0f 84 ?? ?? ?? ?? b9 44 04 00 00 66 3b c1 0f 84}  //weight: 10, accuracy: Low
        $x_5_3 = "SOFTWARE\\Raccine" wide //weight: 5
        $x_10_4 = {57 68 01 00 00 80 ff d6 57 bf 02 00 00 80 57 ff d6 68 ?? ?? ?? ?? 57 ff d6 68 ?? ?? ?? ?? 57 ff d6 68 ?? ?? ?? ?? 57 ff d6 68 ?? ?? ?? ?? 57 ff d6 68 ?? ?? ?? ?? 57 ff d6 68 ?? ?? ?? ?? 57 ff d6 68 ?? ?? ?? ?? 57 ff d6 68 ?? ?? ?? ?? 57 ff d6 68 ?? ?? ?? ?? 57 ff d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

