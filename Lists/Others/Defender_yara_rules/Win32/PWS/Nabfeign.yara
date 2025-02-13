rule PWS_Win32_Nabfeign_A_2147583579_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Nabfeign.A"
        threat_id = "2147583579"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nabfeign"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "NT Kernel & System" wide //weight: 20
        $x_20_2 = "Internet Explorer_Server" ascii //weight: 20
        $x_10_3 = "&pwd=%s" ascii //weight: 10
        $x_10_4 = "&class=" ascii //weight: 10
        $x_4_5 = "KeyHook" ascii //weight: 4
        $x_4_6 = "game_pwd" ascii //weight: 4
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "WindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_4_*))) or
            ((2 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Nabfeign_B_2147583598_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Nabfeign.B"
        threat_id = "2147583598"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nabfeign"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 3e 20 6e 75 6c 00 00 20 2f 63 20 64 65 6c 20 00}  //weight: 2, accuracy: High
        $x_1_2 = {00 43 4f 4d 53 50 45 43 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 46 49 4c 45 00}  //weight: 1, accuracy: High
        $x_3_4 = {40 00 8d 7d e0 a5 a5 89 45 ec a1 ?? ?? 40 00 89 45 f0 8d 45 e0 a4 8b 3d ?? ?? 40 00 33 db 50 be 1f 00 0f 00}  //weight: 3, accuracy: Low
        $x_3_5 = {40 00 56 68 80 00 00 00 6a 02 56 56 68 00 00 00 40 ff 75 0c 89 45 08 ff 15}  //weight: 3, accuracy: High
        $x_3_6 = {00 25 73 0a 00 ?? ?? ?? 5f (70|70) 00 [0-16] 01 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

