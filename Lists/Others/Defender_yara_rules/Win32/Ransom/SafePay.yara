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

