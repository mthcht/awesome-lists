rule PWS_Win32_Reveton_A_2147653348_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Reveton.A"
        threat_id = "2147653348"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 40 14 26 5a e8 ?? ?? ?? ?? 8b 85 ?? ?? ff ff 66 ba bb 01 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Reveton_B_2147681429_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Reveton.B"
        threat_id = "2147681429"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 80 e4 2a 00 00 e8 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 66 ba bb 01 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {9a 02 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_3 = "PokerStars\\user.ini" ascii //weight: 1
        $x_1_4 = "TurboFTP\\addrbk.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

