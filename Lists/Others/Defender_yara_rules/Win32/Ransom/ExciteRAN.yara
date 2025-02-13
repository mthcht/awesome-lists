rule Ransom_Win32_ExciteRAN_SL_2147771865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ExciteRAN.SL!MTB"
        threat_id = "2147771865"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ExciteRAN"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A key i required for decryption, which you can purchase" ascii //weight: 1
        $x_1_2 = "have been encrypted with a special encryption program !!" ascii //weight: 1
        $x_1_3 = "PAY 100$ with Bitcoin to this wallet:" ascii //weight: 1
        $x_1_4 = "ExciteRAN" ascii //weight: 1
        $x_1_5 = "via this contact email \"excite@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

