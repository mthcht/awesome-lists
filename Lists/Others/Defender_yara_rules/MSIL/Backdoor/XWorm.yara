rule Backdoor_MSIL_XWorm_GNQ_2147851646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.GNQ!MTB"
        threat_id = "2147851646"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AAKKq4CKBIAAAYoKQAACgMoFAAABigqAAAK0AUAABs" wide //weight: 1
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "The car is going as fast as it can!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWorm_MBJR_2147892579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.MBJR!MTB"
        threat_id = "2147892579"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 56 71 51 d0 b8 d0 b8 4d d0 b8 d0 b8 d0 b8 d0 b8 45 d0 b8 d0 b8 d0 b8 d0 b8 2f 2f 38 d0 b8 d0 b8 4c 67 d0 b8 d0 b8 d0 b8}  //weight: 1, accuracy: High
        $x_1_2 = "4906-bd89-4b958b0d0c1c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWorm_KAA_2147892848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.KAA!MTB"
        threat_id = "2147892848"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 e3 81 9f 4c 6e 4a 6c 62 47 39 6a e3 81 9f e3 81 9f e3 81 9f 4d e3 81 9f e3 81 9f e3 81 9f e3 81 9f e3}  //weight: 1, accuracy: High
        $x_1_2 = {67 52 45 39 54 49 47 31 76 5a 47 55 75 44 51 30 4b 4a e3 81 9f e3}  //weight: 1, accuracy: High
        $x_1_3 = "ShutdownEventHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWorm_PAEW_2147913786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.PAEW!MTB"
        threat_id = "2147913786"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OxyOxyOron.BaltazaROrion" wide //weight: 2
        $x_2_2 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWorm_GNK_2147917814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.GNK!MTB"
        threat_id = "2147917814"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 02 1b 63 61 11 02 58 11 03 11 00 11 03 19 5f 94 58 61 59 13 01 20 0e 00 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {11 01 11 06 1f 10 63 d2 6f ?? ?? ?? 0a 20 07 00 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWorm_PAFS_2147923128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.PAFS!MTB"
        threat_id = "2147923128"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OfflineKeylogger" wide //weight: 2
        $x_1_2 = "/create /f /RL HIGHEST /sc minute /mo 1 /tn" wide //weight: 1
        $x_1_3 = "WScript.Shell" wide //weight: 1
        $x_2_4 = "/sendMessage?chat_id=" wide //weight: 2
        $x_3_5 = "WizWorm" wide //weight: 3
        $x_2_6 = "shutdown.exe /f /s /t 0" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWorm_PAFT_2147923398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.PAFT!MTB"
        threat_id = "2147923398"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\worms\\." wide //weight: 2
        $x_1_2 = "SELECT * FROM AntiVirusProduct" wide //weight: 1
        $x_1_3 = "No Antivirus" wide //weight: 1
        $x_2_4 = "Black Hat Worm" wide //weight: 2
        $x_2_5 = "SETDESKWALLPAPER" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWorm_GTZ_2147935354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.GTZ!MTB"
        threat_id = "2147935354"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 10 1f 0c 58 28 ?? ?? ?? 06 13 13 02 11 10 1f 10 58 28 ?? ?? ?? 06 13 14 02 11 10 1f 14 58 28 ?? ?? ?? 06 13 15 11 14 16 31 3e 11 14 8d ?? 00 00 01 13 16 02 11 15 11 16 16 11 16 8e 69 28 ?? ?? ?? 0a 7e ?? 00 00 04 12 06 7b ?? 00 00 04 11 0f 11 13 58 11 16 11 16 8e 69 12 04 6f ?? ?? ?? 06 2d 06 73 ?? 00 00 0a 7a 11 10 1f 28 58 13 10 11 12 17 58 13 12 11 12 11 11 32 83}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWorm_AQRA_2147939722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.AQRA!MTB"
        threat_id = "2147939722"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 1c 58 1b 59 91 61 06 09 20 0f 02 00 00 58 20 0e 02 00 00 59 18 59 18 58 06 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 59 20 fb 00 00 00 58 1a 58 17 58 20 00 01 00 00 5d d2 9c 09 17 58 0d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

