rule Ransom_Win32_Ranzylocker_AA_2147798230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ranzylocker.AA!MTB"
        threat_id = "2147798230"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranzylocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 1c 08 41 3b ca 72 25 00 a1 ?? ?? ?? ?? 33 c9 8b 55 ?? 89 45 ?? 85 d2 74 ?? 8b d8 83 7d ?? ?? 8d 45 ?? 0f 43 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

