rule Trojan_Win32_Bundpil_BQ_2147783318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bundpil.BQ!MTB"
        threat_id = "2147783318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bundpil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 15 80 31 00 10 8a 02 a2 90 31 00 10 c7 05 84 31 00 10 0a 00 00 00 0f b6 0d 90 31 00 10 83 f1 79 89 0d 8c 31 00 10}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0d 80 31 00 10 03 4d e4 0f b6 11 33 15 8c 31 00 10 2b 15 84 31 00 10 f7 d2 a1 80 31 00 10 03 45 e4 88 10 eb c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

