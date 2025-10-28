rule Ransom_Win32_RyukCrypt_PB_2147767165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RyukCrypt.PB!MTB"
        threat_id = "2147767165"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RyukCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 83 c1 01 89 4d ?? 8b 55 ?? 3b 15 ?? ?? ?? ?? 7d ?? 8b 45 ?? 0f be 88 ?? ?? ?? ?? 8b 45 ?? 99 f7 3d ?? ?? ?? ?? 0f be 92 ?? ?? ?? ?? 33 ca 8b 45 ?? 88 88 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f0 83 c0 01 89 45 f0 8b 4d f0 0f be 89 ?? ?? ?? ?? 8b 45 ?? 99 f7 3d ?? ?? ?? ?? 0f be 92 ?? ?? ?? ?? 33 ca 8b 45 ?? 88 88 ?? ?? ?? ?? 8b 4d f0 83 c1 01 89 4d f0 8b 55 ?? 89 55 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_RyukCrypt_SH_2147778985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RyukCrypt.SH!MTB"
        threat_id = "2147778985"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RyukCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {51 6a 00 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 f6 89 15 ?? ?? ?? ?? 85 c0 76 3e 8b 3d ?? ?? ?? ?? bb ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 94 31 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 31 3d ?? ?? ?? ?? 75 ?? 6a 00 6a 00 ff d7 a1 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 46 3b f0 72}  //weight: 2, accuracy: Low
        $x_2_2 = {46 3b f0 72 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 54 24 10 52 8b 15 ?? ?? ?? ?? 6a 40 51 52 a3 ?? ?? ?? ?? ff d0 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_RyukCrypt_PH_2147788484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RyukCrypt.PH!MTB"
        threat_id = "2147788484"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RyukCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 04 ba ?? ?? ?? ?? be ?? ?? ?? ?? ba ?? ?? ?? ?? ba ?? ?? ?? ?? ba ?? ?? ?? ?? 31 06 bb ?? ?? ?? ?? 83 c6 04 83 e9 04 83 f9 05 7d ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {bb f4 6a 08 fa 30 06 46 49 83 f9 01 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_RyukCrypt_PH_2147788484_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RyukCrypt.PH!MTB"
        threat_id = "2147788484"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RyukCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncReadMe.html" wide //weight: 1
        $x_1_2 = ".enc" wide //weight: 1
        $x_1_3 = "net stop Antivirus" ascii //weight: 1
        $x_1_4 = "cmd.exe / c vssadmin delete shadows / all / quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

