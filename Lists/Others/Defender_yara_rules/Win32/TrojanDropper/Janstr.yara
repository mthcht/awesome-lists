rule TrojanDropper_Win32_Janstr_A_2147630202_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Janstr.gen!A"
        threat_id = "2147630202"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Janstr"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 81 c4 48 ff ff ff 53 33 c9 89 8d 4c ff ff ff 89 8d 48 ff ff ff 89 8d 50 ff ff ff 89 8d 54 ff ff ff 89 8d 58 ff ff ff 89 4d f0 89 45 fc 33 c0}  //weight: 10, accuracy: High
        $x_10_2 = {b8 80 ed 44 00 e8 c7 fd ff ff 84 c0 74 2c 8d 95 58 ff ff ff}  //weight: 10, accuracy: High
        $x_10_3 = {55 8b ec 81 c4 b8 fe ff ff 53 56 57 33 d2 89 95 c0 fe ff ff 89 95 b8 fe ff ff 89 95 bc fe ff ff 89 95 d0 fe ff ff 89 95 c4 fe ff ff 89 95 cc fe ff ff 89 95 c8 fe ff ff 89 45 fc 8b 45 fc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

