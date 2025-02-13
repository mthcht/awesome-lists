rule VirTool_Win32_TonickInject_2147616686_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/TonickInject"
        threat_id = "2147616686"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TonickInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {66 33 45 d0 0f bf d0 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d4 ff 15}  //weight: 20, accuracy: Low
        $x_20_2 = {66 33 45 d0 0f bf c0 50 e8 ?? ?? ?? ?? 8b d0 8d 4d c8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d d4 e8}  //weight: 20, accuracy: Low
        $x_20_3 = {6b 70 ff fb 12 e7 0b ?? 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c ?? ?? 00 07 f4 01 70 70 ff 1e ?? ?? 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c}  //weight: 20, accuracy: Low
        $x_4_4 = "WriteProcessMemory" ascii //weight: 4
        $x_2_5 = "OvVjhgw^`o|Ck]jse{|z" wide //weight: 2
        $x_2_6 = "WkqppgkIefdoHv" wide //weight: 2
        $x_2_7 = "RgwPmtbimIdbykwd" wide //weight: 2
        $x_2_8 = "SgpqhcS`{ojh" wide //weight: 2
        $x_1_9 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_10 = "VirtualAllocEx" ascii //weight: 1
        $x_1_11 = "SetThreadContext" ascii //weight: 1
        $x_1_12 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 4 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

