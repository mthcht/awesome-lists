rule TrojanDropper_Win32_Zusy_NITA_2147929288_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zusy.NITA!MTB"
        threat_id = "2147929288"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff 15 40 40 40 00 8b e8 85 ed 0f 84 01 01 00 00 55 6a 00 ff 15 44 40 40 00 85 c0 0f 84 f0 00 00 00 50 ff 15 3c 40 40 00 8b f8 85 ff 0f 84 df 00 00 00 8d 4c 24 0c e8 35 18 00 00 8d 54 24 38 c7 84 24 44 01 00 00 00 00 00 00 52 68 04 01 00 00 ff 15 38 40 40 00 8d 44 24 38 8d 4c 24 0c 50 e8 36 18 00 00 68 34 60 40 00 8d 4c 24 10 e8 ec 17 00 00 8d 4c 24 1c e8 19 18 00 00 8b 4c 24 0c}  //weight: 2, accuracy: High
        $x_1_2 = {6a 00 6a 02 e8 0b 16 00 00 8b e8 8d 44 24 10 50 55 c7 44 24 18 28 01 00 00 e8 f0 15 00 00 85 c0 74 5c 8d 4c 24 10 51 55 e8 db 15 00 00 85 c0 74 4d 8b bc 24 3c 01 00 00 8d 74 24 34 8b c7 8a 10 8a 1e 8a ca 3a d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Zusy_AH_2147963182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zusy.AH!MTB"
        threat_id = "2147963182"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "if exist audio\\pwrun.vbs cd audio" ascii //weight: 10
        $x_20_2 = "ren app64.dkc app64.bat" ascii //weight: 20
        $x_30_3 = "start /b /wait app64.bat" ascii //weight: 30
        $x_40_4 = "if exist App64\\admin\\app64.bat cd App64\\admin" ascii //weight: 40
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

