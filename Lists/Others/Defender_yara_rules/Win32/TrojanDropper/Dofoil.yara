rule TrojanDropper_Win32_Dofoil_B_2147812555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dofoil.B"
        threat_id = "2147812555"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 85 98 f6 ff ff 89 95 9c f6 ff ff 8b 85 98 f6 ff ff 8b 8d 9c f6 ff ff 89 8d 88 f2 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

