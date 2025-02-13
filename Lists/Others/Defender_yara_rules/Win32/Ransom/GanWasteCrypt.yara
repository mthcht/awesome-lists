rule Ransom_Win32_GanWasteCrypt_SN_2147757963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GanWasteCrypt.SN!MTB"
        threat_id = "2147757963"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GanWasteCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 11 89 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? 00 00 04 a1 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? bb}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 53 8b 25 ?? ?? ?? 00 58 8b e8 ff 35 ?? ?? ?? 00 ff 35 ?? ?? ?? 00 8b 1d ?? ?? ?? 00 ff e3 5b 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

