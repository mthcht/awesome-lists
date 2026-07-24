rule VirTool_Win64_Xelodesz_A_2147974411_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Xelodesz.A"
        threat_id = "2147974411"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Xelodesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 48 8b f1 48 8b 06 48 8b 4e 08 48 c7 c2 ff ff 1f 00 4d 33 c0 4c 8b 4e 10 4c 8b 56 18 4c 89 54 24 30 4c 8b 5e 20 4c 89 5c 24 38 4d 33 db 4c 89 5c 24 40 4c 89 5c 24 48 4c 89 5c 24 50}  //weight: 1, accuracy: High
        $x_1_2 = {88 43 39 88 4b 38 8b 4f 3c 03 ca 8b c1 c1 e8 18 88 43 3f 8b c1 c1 e8 10 88 43 3e 8b c1 c1 e8 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

