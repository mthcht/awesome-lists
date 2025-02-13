rule Ransom_Win32_CrysisCrypt_SN_2147772414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CrysisCrypt.SN!MTB"
        threat_id = "2147772414"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CrysisCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 06 85 ff 76 ?? 33 c9 89 7c 24 ?? 8b d7 0f af 54 24 ?? 89 54 24 ?? 8b 54 24 ?? 3b 4c 24 ?? 76 ?? 29 54 24 ?? eb 04 01 54 24 ?? 03 4c 24 ?? ff 4c 24 ?? 75 ?? 8a 4c 24 ?? 32 c8 8b 84 24 ?? 00 00 00 01 44 24 ?? 8b 44 24 ?? ff 44 24 ?? 01 44 24 ?? 88 0e 8d 74 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 3b 48 04 0f 82}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

