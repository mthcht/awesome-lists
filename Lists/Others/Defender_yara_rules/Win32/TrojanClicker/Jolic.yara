rule TrojanClicker_Win32_Jolic_A_2147646475_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Jolic.A"
        threat_id = "2147646475"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Jolic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b ce e8 ?? ?? ?? ?? 8b f0 8b 45 ?? 3d 74 70 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {59 8b f0 e9 ?? ?? ?? ?? 3c 3c 0f 85 ?? ?? ?? ?? 81 7f ?? 73 74 6f 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Jolic_A_2147646690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Jolic.gen!A"
        threat_id = "2147646690"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Jolic"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 74 70 6c 00 75}  //weight: 1, accuracy: High
        $x_1_2 = "=pageu" ascii //weight: 1
        $x_1_3 = {3d 72 65 71 00 75}  //weight: 1, accuracy: High
        $x_1_4 = {3d 75 70 64 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

