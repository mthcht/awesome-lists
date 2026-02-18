rule Ransom_Win32_DynoWiper_ADY_2147962555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DynoWiper.ADY!MTB"
        threat_id = "2147962555"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DynoWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 ff d7 f6 c3 01 74 27 8d 4c 24 10 8d 46 61 51 66 89 44 24 14 ff 15 ?? ?? ?? ?? 83 f8 03 75 0f 8d 54 24 10 6a 05 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DynoWiper_AND_2147963263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DynoWiper.AND!MTB"
        threat_id = "2147963263"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DynoWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce d3 e0 85 c2 0f 84 9e 00 00 00 66 0f be c3 c7 45 c8 07 00 00 00 c7 45 c4 01 00 00 00 66 89 45 b4 33 c0 66 89 45 b6 68 ?? 49 42 00 8d 55 b4 c7 45 fc 01 00 00 00 8d 4d d4 e8 ?? ?? ?? ?? 83 c4 04 c6 45 fc 03 83 7d c8 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

