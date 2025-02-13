rule HackTool_Win32_Crenag_A_2147720931_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Crenag.A"
        threat_id = "2147720931"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Crenag"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 68 ff 01 0f 00 b3 01 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 7d fc 8b 35 ?? ?? ?? ?? 83 ff ff 74 ?? 8b cf e8 ?? ?? ?? ?? 84 c0 74 ?? 8b cf e8 ?? ?? ?? ?? 84 c0 74 ?? 6a 00}  //weight: 10, accuracy: Low
        $x_10_2 = {c7 45 e0 a6 06 00 00 50 8d 85 ?? ?? ?? ?? c7 45 e4 00 00 00 00 50 8d 45 e4 c7 45 e8 02 02 00 00 50 8d 85 ?? ?? ?? ?? 50 8d 45 e0 50 8d 85 ?? ?? ?? ?? 50 ff 75 f4 ff 75 f8 6a 00 ff d6}  //weight: 10, accuracy: Low
        $x_1_3 = "UacNagger" wide //weight: 1
        $x_1_4 = "CredNagger" wide //weight: 1
        $x_1_5 = "Hacked!" wide //weight: 1
        $x_1_6 = "Running as high privilege user!" wide //weight: 1
        $x_1_7 = "Password: %ls" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

