rule TrojanDropper_Win32_Tnega_EA_2147788927_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tnega.EA!MTB"
        threat_id = "2147788927"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f2 ae f7 d1 57 8d 3d 21 31 40 00 fc b0 00 b9 ff ff ff ff f2 ae f7 d1 8d 15 21 31 40 00 42 5f 4f 8a 02 88 07 47 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

