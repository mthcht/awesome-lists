rule TrojanSpy_Win32_Tnega_2147758364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tnega!MTB"
        threat_id = "2147758364"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 84 24 ac 00 00 00 30 84 0c ad 00 00 00 41 83 f9 1a 72}  //weight: 1, accuracy: High
        $x_1_2 = {30 4c 05 f5 40 83 f8 0a 73 05 8a 4d f4 eb}  //weight: 1, accuracy: High
        $x_1_3 = {8a 45 b2 30 44 0d b3 41 83 f9 34 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

