rule TrojanDropper_Win32_Purgodoor_A_2147636704_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Purgodoor.A"
        threat_id = "2147636704"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Purgodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d bd 19 fa ff ff f3 ab 66 ab aa 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 95 18 fa ff ff 52 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "71572690-1156-4e36-9F2A-42587899ABDE" ascii //weight: 1
        $x_1_3 = {62 2e 64 6c 6c [0-4] 70 2e 64 6c 6c [0-4] 73 2e 65 78 65 [0-4] 71 2e 65 78 65 [0-4] 32 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {45 52 2e 45 58 45 [0-4] 50 4c 4f 52 [0-4] 45 58 [0-4] 25 73 25 73 25 73}  //weight: 1, accuracy: Low
        $x_1_5 = {25 64 25 64 25 64 2e 63 61 62 [0-4] 6d 61 6b 65 63 61 62 20 25 73 20 25 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

