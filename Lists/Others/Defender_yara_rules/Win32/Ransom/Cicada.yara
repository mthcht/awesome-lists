rule Ransom_Win32_Cicada_DA_2147920620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cicada.DA!MTB"
        threat_id = "2147920620"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cicada"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 69 6e 5f 65 6e 63 [0-2] 65 6e 63 72 79 70 74 69 6f 6e [0-2] 65 6e 63 72 79 70 74 5f 66 69 6c 65 [0-2] 5f 4f 42 46 42 59 54 45 53 5f 53 44 41 54 41}  //weight: 1, accuracy: Low
        $x_1_2 = {77 69 6e 5f 65 6e 63 [0-2] 65 6e 63 72 79 70 74 69 6f 6e [0-2] 63 72 65 61 74 65 5f 66 69 6c 65 5f 72 65 63 6f 76 65 72 79 [0-2] 5f 4f 42 46 42 59 54 45 53 5f 53 44 41 54 41}  //weight: 1, accuracy: Low
        $x_1_3 = {77 69 6e 5f 65 6e 63 [0-2] 65 6e 63 72 79 70 74 69 6f 6e [0-2] 65 63 6e 72 79 70 74 65 64 5f 66 69 6c 65 73 5f 66 75 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "RECOVER--DATA.txt" ascii //weight: 1
        $x_1_5 = "taskkill /IM * /F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cicada_MKV_2147934897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cicada.MKV!MTB"
        threat_id = "2147934897"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cicada"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c7 08 39 f9 75 ?? 85 d2 74 ?? 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 0f b6 94 0c d8 00 00 00 30 14 08 41 39 cb 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

