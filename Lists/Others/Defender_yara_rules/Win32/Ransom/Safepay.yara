rule Ransom_Win32_Safepay_B_2147932533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Safepay.B"
        threat_id = "2147932533"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Safepay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 00 73 00 2d 00 6e 00 65 00 74 00 64 00 72 00 69 00 76 00 65 00 00 00 2d 00 70 00 61 00 73 00 73 00 3d 00 00 00 2d 00 65 00 6e 00 63 00 3d 00 00 00 2d 00 6c 00 6f 00 67 00 00 00 2d 00 75 00 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

