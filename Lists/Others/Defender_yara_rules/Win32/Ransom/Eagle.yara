rule Ransom_Win32_Eagle_C_2147839301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Eagle.C!dha"
        threat_id = "2147839301"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Eagle"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pqrstOPghijklm963nouwz0214587.-JKLMNvQRSxyTUDEFGHIVWXYZabcdefABC" ascii //weight: 1
        $x_1_2 = {c7 44 24 08 0f 00 00 00 b8 01 02 04 08 f7 eb c7 44 24 0c 00 00 00 00 25 11 11 11 11 83 e2 01 89 04 24 89 54 24 04 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

