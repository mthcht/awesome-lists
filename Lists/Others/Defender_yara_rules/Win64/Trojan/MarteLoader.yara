rule Trojan_Win64_MarteLoader_YAF_2147945309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MarteLoader.YAF!MTB"
        threat_id = "2147945309"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MarteLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 0c 0a 33 c1 48 63 4c 24 28 48 8b 94 24 40 01 00 00 88 04}  //weight: 10, accuracy: High
        $x_10_2 = {48 8d 15 5c 80 02 00 48 8d 4c 24 6c e8 ?? ?? ?? ?? 85 c0 75 08 c7 44}  //weight: 10, accuracy: Low
        $x_1_3 = "GoldVekRogerS" wide //weight: 1
        $x_1_4 = "AvastSvc.exe" wide //weight: 1
        $x_1_5 = "bdagent.exe" wide //weight: 1
        $x_1_6 = "ekrn.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

