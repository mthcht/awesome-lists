rule Trojan_Win64_Comei_NC_2147966315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Comei.NC!MTB"
        threat_id = "2147966315"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Comei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 05 8b 9a 5e 00 90 48 89 04 24 48 c7 44 24 08 00 00 00 00 48 c7 44 24 10 00 00 80 00 48 c7 44 24 18 00 30 00 00 48 c7 44 24 20 04 00 00 00 66 90 e8 db 76 02 00 45 0f 57 ff 4c 8b 35 98 70 69 00 65 4d 8b 36 4d 8b 36 48 8b 44 24 28 0f 1f 40 00 48 85 c0 0f 84 dc 01 00 00 48 8b 94 24 b8 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {48 8d 0d 31 c3 69 00 e8 2c 1d 00 00 48 85 c0 0f 84 90 00 00 00 4c 8b 8c 24 d0 00 00 00 49 8b 19 4d 8b 51 08 49 89 01 4c 8b 5c 24 48 49 c1 eb 03 4d 89 59 10 49 8b 49 08 4c 39 d1 49 0f 4f ca 48 39 d8 74 11 48 c1 e1 03}  //weight: 1, accuracy: High
        $x_1_3 = "killing Cmdexec" ascii //weight: 1
        $x_1_4 = "discordleveldb" ascii //weight: 1
        $x_1_5 = "GETGet200404443tcp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

