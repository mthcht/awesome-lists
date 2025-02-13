rule VirTool_WinNT_Fispids_A_2147606854_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Fispids.gen!A"
        threat_id = "2147606854"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Fispids"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 dc e9 2b ca 83 e9 05 89 4d dd 6a 05 52 8d 45 dc 50 e8 ?? ?? ff ff 33 ff eb 1b}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 d4 e9 2b c6 83 e8 05 89 45 d5 6a 05 56 8d 45 d4 50 e8 ?? ?? ff ff 33 f6 eb 1b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_WinNT_Fispids_B_2147607767_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Fispids.gen!B"
        threat_id = "2147607767"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Fispids"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 dc e9 2b cf 83 e9 05 89 4d dd 6a 05 57 8d 45 dc 50 e8 ?? ?? ff ff 33 ff eb 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Fispids_C_2147607860_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Fispids.gen!C"
        threat_id = "2147607860"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Fispids"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 dc e9 2b c7 83 e8 05 89 45 dd [0-1] 6a 05 57 8d 45 dc 50 e8 ?? ?? ff ff 33 ff eb 1b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Fispids_D_2147608073_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Fispids.gen!D"
        threat_id = "2147608073"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Fispids"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 dc e9 2b (c1|ca) 83 (e8|e9) 05 89 (45|4d) dd 6a 05 (51|52) 8d 45 dc 50 e8 ?? ?? ff ff 33 ff eb 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

