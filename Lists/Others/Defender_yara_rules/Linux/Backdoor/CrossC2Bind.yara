rule Backdoor_Linux_CrossC2Bind_A_2147782838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/CrossC2Bind.gen!A!!CrossC2Bind.gen!A"
        threat_id = "2147782838"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "CrossC2Bind"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "CrossC2Bind: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 88 d3 80 f3 ff 45 88 de 41 80 f6 ff 80 f2 00 41 88 df 41 80 e7 00 41 20 d2 45 88 f4 41 80 e4 00 41 20 d3 45 08 d7 45 08 dc 45 30 e7 44 08 f3 80 f3 ff 80 ca 00 20 d3 41 08 df 41 f6 c7 01 0f 45 c1 4c 8b ad 20 ff ff ff 41 89 45 00 48 83 ec 0a 50 68 b1 46 75 25}  //weight: 2, accuracy: High
        $x_2_2 = {0f af d7 83 e2 01 83 fa 00 41 0f 94 c0 83 fe 0a 41 0f 9c c1 45 88 c2 45 20 ca 45 30 c8 45 08 c2 41 f6 c2 01 0f 45 c1 4c 8b 9d 20 ff ff ff 41 89 03 48 83 ec 0a 50}  //weight: 2, accuracy: High
        $x_2_3 = {0f 9c c0 44 88 e9 80 f1 ff 40 88 c7 40 80 f7 ff 41 80 f4 00 41 88 c8 41 80 e0 00 45 20 e5 41 88 f9 41 80 e1 00 44 20 e0 45 08 e8 41 08 c1 45 30 c8 40 08 f9 80 f1 ff 41 80 cc 00 44 20 e1 41 08 c8 41 f6 c0 01 0f 45 d6}  //weight: 2, accuracy: High
        $x_2_4 = {0f af f3 83 e6 01 83 fe 00 0f 94 c6 83 ff 0a 0f 9c c3 88 f7 80 f7 ff 89 85 2c f3 ff ff 88 d8 34 ff 80 f2 01 88 fc 80 e4 ff 20 d6 88 85 2b f3 ff ff 24 ff 20 d3 08 f4 08 d8 30 c4 8a 85 2b f3 ff ff 08 c7 80 f7 ff 80 ca 01 20 d7 08 fc f6 c4 01 8b b5 2c f3 ff ff 0f 45 f1 8b 8d e4 fe ff ff 89 31 83 ec 0a 50 31 c0 0f 84 01}  //weight: 2, accuracy: High
        $x_2_5 = {83 e6 01 83 fe 00 0f 94 c2 83 ff 0a 0f 9c c6 88 d3 20 f3 30 f2 08 d3 f6 c3 01 0f 45 c1 8b 8d e4 fe ff ff 89 01 83 ec 0a 50 31 c0 0f 84 01}  //weight: 2, accuracy: High
        $x_2_6 = {89 df 01 f7 0f af df 83 e3 01 83 fb 00 0f 94 c3 83 f8 0a 0f 9c c7 88 d8 20 f8 30 fb 08 d8 a8 01 0f 45 ca 8b 95 e4 fe ff ff 89 0a 83 ec 0a 50 31 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

