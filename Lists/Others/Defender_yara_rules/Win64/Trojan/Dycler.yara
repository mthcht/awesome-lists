rule Trojan_Win64_Dycler_MK_2147967849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dycler.MK!MTB"
        threat_id = "2147967849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dycler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {44 31 c0 89 c2 c1 ea 11 31 c2 89 d1 c1 e1 05 31 d1 48 01 f1 48 89 c8 49 f7 e7 4d 01 d3 c1 e2 04 8d 04 92 29 c1 41 0f b7 04 4c 41 0f b7 09 41 80 fb 02}  //weight: 20, accuracy: High
        $x_15_2 = {66 c7 84 24 2c 05 00 00 4b 7e 66 c7 84 24 2e 05 00 00 03 81 66 c7 84 24 30 05 00 00 e3 81 66 c7 84 24 32 05 00 00 92 7e 66 c7 84 24 34 05 00 00 4c 81 66 c7 84 24 36 05 00 00 7e 81 66 c7 84 24 38 05 00 00 f9 7e 66 c7 84 24 3a 05 00 00 49 81 66 c7 84 24 3c 05 00 00 fc 81}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

