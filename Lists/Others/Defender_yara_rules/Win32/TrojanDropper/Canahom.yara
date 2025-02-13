rule TrojanDropper_Win32_Canahom_A_2147597870_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Canahom.A"
        threat_id = "2147597870"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Canahom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 85 84 fd ff ff 3c 44 14 13 8d 85 cc fc ff ff 50 ff 75 9c ff 15 34 4b 14 13 ff 75 9c ff 15 38 4b 14 13 5f}  //weight: 1, accuracy: High
        $x_1_2 = {ad 8b f7 33 c2 42 3d 53 6f 66 74 75 f3 4a ac 32 c2 aa 83 c2 02 e2 f6 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

