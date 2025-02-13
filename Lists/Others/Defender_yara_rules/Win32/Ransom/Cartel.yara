rule Ransom_Win32_Cartel_AA_2147822382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cartel.AA!MTB"
        threat_id = "2147822382"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cartel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 01 0f b7 45 ?? 8b 4d ?? 0f b6 04 01 03 d0 0f b6 4d ?? 03 d1 81 e2 ff 00 00 00 88 55 ?? 0f b7 55 ?? 8b 45 ?? 8a 0c 10 88 4d ?? 0f b6 55 ?? 0f b7 45 f8 8b 4d ?? 8b 75 ?? 8a 14 16 88 14 01 0f b6 45}  //weight: 1, accuracy: Low
        $x_1_2 = "/c vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

