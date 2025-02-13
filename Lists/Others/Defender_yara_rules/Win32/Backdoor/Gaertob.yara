rule Backdoor_Win32_Gaertob_A_2147619071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Gaertob.A"
        threat_id = "2147619071"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Gaertob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 6a 00 6a 0c 68 ?? ?? ?? ?? ff b5 ?? ?? ff ff ff 15 ?? ?? ?? ?? 6a 01 58 85 c0 0f 84 ?? ?? 00 00 6a 00 6a 63}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff 52 c6 85 ?? ff ff ff 61 c6 85 ?? ff ff ff 72 c6 85 ?? ff ff ff 21 c6 85 ?? ff ff ff 1a}  //weight: 1, accuracy: Low
        $x_1_3 = {89 45 f8 83 7d f8 03 74 06 83 7d f8 04 75 14 8d 45 fc 50 ff 15 ?? ?? ?? ?? 83 f8 01 75 05 e8 ?? ?? ?? ?? 8a 45 fc 2c 01 88 45 fc 0f be 45 fc 83 f8 62 75 c2}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 65 70 65 6e 74 68 65 73 [0-4] 63 75 72 72 65 6e 74 75 73 65 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

