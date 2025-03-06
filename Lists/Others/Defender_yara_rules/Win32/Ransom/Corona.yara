rule Ransom_Win32_Corona_MKV_2147935318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Corona.MKV!MTB"
        threat_id = "2147935318"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Corona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c8 b8 81 80 80 80 f7 e1 c1 ea 07 8d 44 11 01 8b 4c 24 38 88 04 31 30 06 8b 44 24 2c 47 46 3b f8 72 c4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

