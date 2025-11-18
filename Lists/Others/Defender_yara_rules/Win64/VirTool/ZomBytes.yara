rule VirTool_Win64_ZomBytes_C_2147949850_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/ZomBytes.C"
        threat_id = "2147949850"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ZomBytes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 2a 5d 20 4d 65 6d 6f 72 79 20 61 6c 6c 6f 63 61 74 65 64 20 77 69 74 68 20 73 75 63 63 65 73 73 20 21 20 41 64 64 72 65 73 73 20 3a 20 25 70 0a 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "[!] Can't allocate memory ! STATUS : 0x%ll" ascii //weight: 1
        $x_1_3 = "draugr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_ZomBytes_B_2147949859_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/ZomBytes.B"
        threat_id = "2147949859"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ZomBytes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 2b 67 38 4c 8b 5f 40 4c 89 1c 24 48 2b 67 20 4c 8b 5f 28 4c 89 1c 24 48 2b 67 30 4c 8b 5f 50 4c 89 1c 24 49 89 f3 4c 89 67 08}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 fb 49 89 ca 48 8b 47 48 41 ff e3}  //weight: 1, accuracy: High
        $x_1_3 = {48 03 63 30 48 03 63 20 48 03 63 38 48 8b 59 10 48 8b 79 18 48 8b 71 58 4c 8b 61 60 4c 8b 69 68 4c 8b 71 70 4c 8b 79 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

