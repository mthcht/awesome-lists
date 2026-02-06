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

