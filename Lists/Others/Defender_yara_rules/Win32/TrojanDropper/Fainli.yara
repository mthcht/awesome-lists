rule TrojanDropper_Win32_Fainli_A_2147804009_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Fainli.A"
        threat_id = "2147804009"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Fainli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 44 24 0c 20 ff 4c 24 14 0f 85 e2 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 0c 6a 0a 83 c0 04 50 53 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

