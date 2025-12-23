rule Trojan_Win64_SilverFox_AHB_2147959959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilverFox.AHB!MTB"
        threat_id = "2147959959"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilverFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {49 4e 43 52 45 41 53 49 4e 47 20 52 45 56 45 41 4c 20 53 54 4f 4f 44 20 56 41 4c 49 44 41 54 49 4f 4e 20 46 41 56 4f 55 52 49 54 45 00 00 00 00}  //weight: 30, accuracy: High
        $x_20_2 = "cmd /v /c Set JmwA=cmd & !JmwA! < Passive.eml" ascii //weight: 20
        $x_10_3 = {26 8a 01 2c ?? 80 39 ?? 0f b6 d0 0f b6 01 0f 4c d0 44 0f be c2 41 8d 40 bf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

