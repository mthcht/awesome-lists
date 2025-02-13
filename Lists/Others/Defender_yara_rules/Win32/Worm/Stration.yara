rule Worm_Win32_Stration_ST_2147605114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Stration.ST"
        threat_id = "2147605114"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Stration"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 49 00 8a 5c 04 0c 8a 4c 24 30 32 d9 88 5c 04 0c 40 83 f8 25 7c ec}  //weight: 2, accuracy: High
        $x_1_2 = {57 8d 54 24 ?? 52 33 ?? ?? 8d 44 ?? ?? 50 68 ?? ?? ?? ?? ?? ?? c7 44 ?? ?? 00 00 00 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 24 6a ff 57 ff 15 ?? ?? ?? ?? 8d 4c ?? ?? 51 57 ff 15 ?? ?? ?? ?? 85 c0 74 04}  //weight: 1, accuracy: Low
        $x_1_3 = "SetUnhandledExceptionFilter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Stration_SZ_2147606505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Stration.SZ"
        threat_id = "2147606505"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Stration"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 53 79 73 74 65 6d 33 32 5c 6f 64 66 ?? 62 63}  //weight: 5, accuracy: Low
        $x_4_2 = {49 6d 70 65 72 73 6f 6e 61 74 65 00 53 68 75 74 64 6f 77 6e 00 00 00 00 44 6c 6c 4e 61 6d 65 00 25 73 25 73 2e 75 30 30}  //weight: 4, accuracy: High
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\iexplore" ascii //weight: 2
        $x_1_4 = "{EC72CF68-F870-44b1-853C-9DC13F447FE9}" ascii //weight: 1
        $x_1_5 = "{22805D67-DE18-49f7-97B9-4C859C845489}" ascii //weight: 1
        $x_1_6 = "EnumProcessModules" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

