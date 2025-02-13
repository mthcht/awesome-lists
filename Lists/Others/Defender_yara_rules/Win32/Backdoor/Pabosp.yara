rule Backdoor_Win32_Pabosp_2147690016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pabosp"
        threat_id = "2147690016"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pabosp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 4c 24 08 51 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 ?? 6a 05 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 54 24 04 8b 44 24 00 89 42 04 b0 01}  //weight: 5, accuracy: Low
        $x_2_2 = "avgsp.exe" ascii //weight: 2
        $x_2_3 = "MakeAndShowEgg" ascii //weight: 2
        $x_2_4 = "DeleteMyself" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

