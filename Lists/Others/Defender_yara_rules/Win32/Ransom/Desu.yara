rule Ransom_Win32_Desu_MKV_2147951413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Desu.MKV!MTB"
        threat_id = "2147951413"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Desu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e7 c1 ea 02 8d 04 52 03 c0 2b c8 8a 04 39 8b 4d ?? 32 04 3b 88 04 39 47 3b 7d 18 72}  //weight: 5, accuracy: Low
        $x_2_2 = "SORRY! Your files are encrypted" ascii //weight: 2
        $x_1_3 = "desu ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

