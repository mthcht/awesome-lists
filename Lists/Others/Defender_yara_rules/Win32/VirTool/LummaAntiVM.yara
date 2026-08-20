rule VirTool_Win32_LummaAntiVM_A_2147976449_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/LummaAntiVM.A"
        threat_id = "2147976449"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaAntiVM"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 48 89 e5 48 83 ec 20 e8 ?? ?? ?? ?? 85 c0 74 07 b8 01 00 00 00 eb 15 e8 ?? ?? ?? ?? 85 c0 74 07 b8 01 00 00 00 eb 05 b8 00 00 00 00 48 83 c4 20 5d c3}  //weight: 2, accuracy: Low
        $x_1_2 = "ipinfo.io" ascii //weight: 1
        $x_1_3 = "what-is-my-ip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

