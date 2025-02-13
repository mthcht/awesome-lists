rule TrojanDropper_Win32_Conhook_A_2147800914_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Conhook.A"
        threat_id = "2147800914"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HookProc" ascii //weight: 10
        $x_10_2 = {72 65 6d 6f 76 61 6c 66 69 6c 65 2e 62 61 74 00 40 65 63 68 6f 20 6f 66 66}  //weight: 10, accuracy: High
        $x_10_3 = "if exist %1 goto df" ascii //weight: 10
        $x_10_4 = "Activate" ascii //weight: 10
        $x_2_5 = {8b c0 50 58 90}  //weight: 2, accuracy: High
        $x_2_6 = {87 c0 87 db 86 db 90}  //weight: 2, accuracy: High
        $x_2_7 = {53 53 6a 02 53 53}  //weight: 2, accuracy: High
        $x_2_8 = {0f af c8 0f af 4d f0 0f af 4d f0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

