rule Ransom_Win32_ClopCrypt_PA_2147765499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ClopCrypt.PA!MTB"
        threat_id = "2147765499"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ClopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c1 00 20 00 00 89 4d ?? 8b 95 ?? ?? ff ff 2b 55 98 89 95 ?? ?? ff ff 8b 45 ?? 99 b9 00 c0 0f 00 f7 f9 89 45 ?? 8b 55 ?? 81 c2 00 10 00 00 89 55 ?? 8b 85 ?? ?? ff ff 33 85 ?? ?? ff ff 89 85 ?? ?? ff ff 8b 4d ?? 81 c1 00 f0 ff 0f 89 4d ?? c1 85 ?? ?? ff ff 07 8b 55 ?? 81 ea cc 34 00 00 89 55 ?? 8b 85 ?? ?? ff ff 33 85 ?? ?? ff ff 89 85 ?? ?? ff ff 8b 4d ?? 8b 55 ?? 8b 85 ?? ?? ff ff 89 04 8a e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ClopCrypt_PA_2147765499_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ClopCrypt.PA!MTB"
        threat_id = "2147765499"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ClopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c C:\\Windows\\System32\\wbem\\WMIC.exe shadowcopy where \"ID='%s'\" delete" wide //weight: 1
        $x_1_2 = "%s\\!A_READ_ME.TXT" wide //weight: 1
        $x_1_3 = ".CI_0P" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

