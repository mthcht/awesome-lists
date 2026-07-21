rule HackTool_Linux_Looptik_A_2147974163_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Looptik.A"
        threat_id = "2147974163"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Looptik"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ec 18 8d 05 ?? ?? ?? ?? 89 04 24 c7 44 24 04 13 00 00 00 e8 ?? ?? ?? ?? 8b 44 24 10 85 c0 74 ?? c6 44 24 1c 00 83 c4 18 c3}  //weight: 2, accuracy: Low
        $x_2_2 = {83 ec 18 8d 05 ?? ?? ?? ?? 89 04 24 c7 44 24 04 1c 00 00 00 e8 ?? ?? ?? ?? 8b 44 24 10 85 c0 74 ?? 8d 05 ?? ?? ?? ?? 89 04 24 c7 44 24 04 19 00 00 00 e8 ?? ?? ?? ?? 8b 44 24 10 85 c0 74 ?? c6 44 24 1c 00 83 c4 18 c3}  //weight: 2, accuracy: Low
        $x_2_3 = {8d 05 55 88 15 08 89 04 24 c7 44 24 04 07 00 00 00 8d 44 24 54 89 44 24 08 c7 44 24 0c 02 00 00 00 c7 44 24 10 02 00 00 00 e8 38 46 ff ff 8b 44 24 14 8b 0d c8 76 2f 09 8d 15 0c 19 22 09 89 50 30}  //weight: 2, accuracy: High
        $x_2_4 = {55 48 89 e5 48 83 ec 10 48 8d 05 ?? ?? ?? ?? bb 0d 00 00 00 e8 ?? ?? ?? ?? 48 83 c4 10 5d c3}  //weight: 2, accuracy: Low
        $x_2_5 = {55 48 89 e5 48 83 ec 10 90 48 8d 05 a0 37 03 00 bb 03 00 00 00 0f 1f 44 00 00 e8 3b 59 ff ff 48 85 c9 75 44 48 8d 05 39 76 03 00 bb 15 00 00 00 e8 05 7e fd ff 0f 1f 44 00 00 48 85 c9 74 16 48 8d 05 5b 63 03 00 bb 11 00 00 00 e8 ea 7d fd ff 48 85 c9 75 08 31 c0 48 83 c4 10 5d c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

