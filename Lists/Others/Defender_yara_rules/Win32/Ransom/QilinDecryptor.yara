rule Ransom_Win32_QilinDecryptor_YTD_2147922509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/QilinDecryptor.YTD!MTB"
        threat_id = "2147922509"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "QilinDecryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 5c 10 ff 8b 75 08 30 1c 0e 41 3b 55 d0 73 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

