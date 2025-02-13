rule Ransom_Win32_Nokoyawa_MK_2147843063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nokoyawa.MK!MTB"
        threat_id = "2147843063"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokoyawa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8b 45 ?? 8a 14 10 8b 4d ?? 8b 45 ?? 32 14 01 8b 4d ?? 8b 45 ?? 88 14 08 ff 45 ?? 8b 55 ?? 3b 55 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

