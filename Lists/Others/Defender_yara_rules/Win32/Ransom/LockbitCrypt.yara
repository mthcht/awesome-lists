rule Ransom_Win32_LockbitCrypt_SN_2147758924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockbitCrypt.SN!MTB"
        threat_id = "2147758924"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockbitCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 f6 ff d7 55 55 55 55 55 55 ff d3 81 fe ?? ?? ?? ?? 7e ?? 81 7c 24 ?? ?? ?? ?? ?? 74 ?? 81 7c 24 ?? ?? ?? ?? ?? 75 ?? 46 8b c6 99 83 fa 01 7c ?? 7f ?? 3d ?? ?? ?? ?? 72}  //weight: 2, accuracy: Low
        $x_2_2 = {52 6a 40 51 50 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? bb ?? ?? ?? ?? eb ?? 8d 49 00 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 55 55 ff d6 55 ff d7 4b 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockbitCrypt_SV_2147773815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockbitCrypt.SV!MTB"
        threat_id = "2147773815"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockbitCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 04 68 00 10 00 00 8b 85 ?? ?? ?? ?? ff 70 ?? 6a 00 ff 55 ?? 89 45}  //weight: 2, accuracy: Low
        $x_2_2 = {eb 03 c2 0c 00 55 8b ec 81 ec ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 83 c4 ?? e8 ?? ?? 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

