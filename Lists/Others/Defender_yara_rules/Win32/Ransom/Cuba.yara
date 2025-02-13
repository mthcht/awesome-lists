rule Ransom_Win32_Cuba_RMA_2147819636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cuba.RMA!MTB"
        threat_id = "2147819636"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cuba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 ?? c7 45 ?? 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8a a5 08 00 c7 [0-10] e3 14 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cuba_MKV_2147909058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cuba.MKV!MTB"
        threat_id = "2147909058"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cuba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f0 2b f8 8d 4d ?? 03 ca 42 8a 04 0e 32 01 88 04 0f 8b 4d 10 3b d1 72}  //weight: 1, accuracy: Low
        $x_1_2 = "All your files are encrypted" ascii //weight: 1
        $x_1_3 = "Do not rename encrypted files." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

