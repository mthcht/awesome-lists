rule Ransom_Win32_SafePay_MKV_2147953701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SafePay.MKV!MTB"
        threat_id = "2147953701"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SafePay"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {32 02 32 c1 34 71 88 44 0d cf 41 83 f9 11 72 ec}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_SafePay_C_2147959590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SafePay.C"
        threat_id = "2147959590"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SafePay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 02 8d 52 01 8b ce c1 e6 08 c1 e9 18 33 c8 0f b6 c1}  //weight: 1, accuracy: High
        $x_1_2 = {3d 2c 08 00 00 77 1f 74 24 3d 19 08 00 00 77 25 3d 18 08 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

