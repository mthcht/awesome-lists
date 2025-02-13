rule Backdoor_Win32_Doumol_A_2147610924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Doumol.A"
        threat_id = "2147610924"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Doumol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fe 03 74 05 80 fb 03 75 37 8b c3 e8 ?? ?? ?? ?? 83 fa ff 75 03 83 f8 ff 74 26}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 ba 06 00 00 00 e8 ?? ?? ?? ?? 83 c3 24 4e 0f 85 65 ff ff ff 83 7d f4 00 0f 85 23 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 95 58 ff ff ff 8b c6 8b 08 ff 51 38 43 83 fb 0a 75 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

