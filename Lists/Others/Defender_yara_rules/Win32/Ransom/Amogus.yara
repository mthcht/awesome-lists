rule Ransom_Win32_Amogus_PA_2147916254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Amogus.PA!MTB"
        threat_id = "2147916254"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Amogus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".amogus" ascii //weight: 1
        $x_4_2 = {0f b6 56 01 83 c7 10 83 c6 10 32 53 01 88 57 ?? 8b 4c 24 ?? 0f b6 56 ?? 32 53 02 88 51 02 8b 4c 24 ?? 0f b6 56 ?? 32 53 03 88 51 03 8b 54 24 ?? 0f b6 4e ?? 32 4b 04 88 4a 04}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

