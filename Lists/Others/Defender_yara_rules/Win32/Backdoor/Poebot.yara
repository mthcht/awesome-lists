rule Backdoor_Win32_Poebot_2147596763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poebot"
        threat_id = "2147596763"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 35 ?? ?? ?? 00 68 ?? ?? ?? 00 8d 85 a4 ee ff ff 50 e8 ?? ?? 00 00 83 c4 20 83 a5 d8 ee ff ff 00 eb 0d 8b 85 d8 ee ff ff 40 89 85 d8 ee ff ff 83 bd d8 ee ff ff 0a 75 05 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 85 a4 ee ff ff 50 e8 89 02 00 00 83 c4 20 89 bd d8 ee ff ff 83 bd d8 ee ff ff 0a 75 05 e8 ?? ?? ff ff 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

