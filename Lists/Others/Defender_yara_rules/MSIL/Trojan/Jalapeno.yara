rule Trojan_MSIL_Jalapeno_AJL_2147910601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AJL!MTB"
        threat_id = "2147910601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 26 13 14 20 b4 00 00 00 95 58 80 ?? 00 00 04 11 2c 7e ?? 00 00 04 20 26 04 00 00 95 58 13 2c 11 2c 7e ?? 00 00 04 20 22 04 00 00 95 33 50 11 28 7e ?? 00 00 04 25 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "kbdes2Seard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AJL_2147910601_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AJL!MTB"
        threat_id = "2147910601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tilesetter 2024" wide //weight: 1
        $x_2_2 = "20F3B949-149A-4515-B752-5497C04E16D4" ascii //weight: 2
        $x_5_3 = "Burstein.dll" wide //weight: 5
        $x_5_4 = "Burstein Applebee" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AJL_2147910601_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AJL!MTB"
        threat_id = "2147910601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Steam Unlocker.exe" wide //weight: 10
        $x_10_2 = "0d4bf89c-3b30-4d70-bac8-5b9a0a979592" ascii //weight: 10
        $x_10_3 = "Daniel\\source\\repos\\Steam Unlocker\\Steam Unlocker\\obj\\Release\\Steam Unlocker.pdb" ascii //weight: 10
        $x_10_4 = "Trying elevate previleges to administrator" wide //weight: 10
        $x_5_5 = "http://adpk.duckdns.org:58630" wide //weight: 5
        $x_5_6 = "http://3.80.28.180/IwwpdjJD/chan.exe" wide //weight: 5
        $x_1_7 = "\\AppData\\Roaming\\Microsoft\\Windows\\FILE.exe" wide //weight: 1
        $x_1_8 = "\\AppData\\Roaming\\Microsoft\\Windows\\chan.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Jalapeno_OXAA_2147912526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.OXAA!MTB"
        threat_id = "2147912526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 13 0a 2b 2b 11 05 11 0a 8f 29 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd}  //weight: 5, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "ReverseDecode" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "IsLogging" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NE_2147913834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NE!MTB"
        threat_id = "2147913834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 00 95 11 05 13 05 61}  //weight: 5, accuracy: High
        $x_5_2 = {00 00 95 11 0f 13 0f 61}  //weight: 5, accuracy: High
        $x_5_3 = {95 11 0a 13 0a 61}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SCAA_2147916554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SCAA!MTB"
        threat_id = "2147916554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 02 06 91 66 d2 9c 08}  //weight: 1, accuracy: High
        $x_2_2 = {02 06 8f 24 00 00 01 25 71 ?? 00 00 01 20 ?? 00 00 00 59 d2 81 ?? 00 00 01 08}  //weight: 2, accuracy: Low
        $x_2_3 = {02 06 8f 24 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SNAA_2147916916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SNAA!MTB"
        threat_id = "2147916916"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 05 6f ?? 00 00 0a 11 05 20 00 01 00 00 5d d2 59 20 ff 00 00 00 5f d2 13 06 11 06 0f 02 28 ?? 00 00 0a 20 00 01 00 00 5d d2 61 d2 13 06 11 04 11 05 11 06 6f ?? 00 00 0a 00 00 11 05 17 58 13 05 11 05 11 04 6f ?? 00 00 0a fe 04 13 07 11 07 2d ab}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NL_2147917177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NL!MTB"
        threat_id = "2147917177"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7e 02 00 00 04 7e ?? 00 00 04 6f ?? 00 00 0a 73 ?? 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 72 ?? 00 00 70 7e ?? 00 00 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 25}  //weight: 3, accuracy: Low
        $x_1_2 = "PorroQuisquamEst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NL_2147917177_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NL!MTB"
        threat_id = "2147917177"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {02 7b bc 01 00 04 1c 8d 78 00 00 01 25 16 02 7c b8 00 00 04 28 57 00 00 0a a2 25 17 72 95 32 00 70 a2 25 18 02 7c b6 00 00 04 28 57 00 00 0a a2 25 19 72 a7 32 00 70 a2 25 1a 02 7c b7 00 00 04 28 57 00 00 0a a2 25 1b 72 ab 32 00 70 a2 28 5e 00 00 0a 6f 2a 00 00 0a}  //weight: 3, accuracy: High
        $x_1_2 = "done_droped" wide //weight: 1
        $x_1_3 = "eDba.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SWAA_2147917323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SWAA!MTB"
        threat_id = "2147917323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {15 59 91 61 ?? 08 20 0d 02 00 00 58 20 0c 02 00 00 59 1d 59 1d 58 ?? 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_PPF_2147917736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.PPF!MTB"
        threat_id = "2147917736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cdn.gosth.ltd/launcher.exe" wide //weight: 2
        $x_2_2 = "Temp\\eu.png" wide //weight: 2
        $x_1_3 = "Gosth Injected!" wide //weight: 1
        $x_1_4 = "all traces destroyed!" wide //weight: 1
        $x_1_5 = "Self Delete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_PJ_2147917932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.PJ!MTB"
        threat_id = "2147917932"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 5a 03 00 0a 0d 08 6f ?? ?? ?? 0a 16 09 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 13 04 06 7e 4a 01 00 04 11 04 08 6f ?? ?? ?? 0a 08 2c 06}  //weight: 2, accuracy: Low
        $x_2_2 = {7e 4a 01 00 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 26 7e 4c 01 00 04 28 ?? ?? ?? 0a de 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NJ_2147917953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NJ!MTB"
        threat_id = "2147917953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {28 fb 03 00 0a 6f fc 03 00 0a 28 fd 03 00 0a 28 fe 03 00 0a 28 07 00 00 2b 17 fe 02 0a 06}  //weight: 3, accuracy: High
        $x_1_2 = "SuDungSoLuong" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NJ_2147917953_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NJ!MTB"
        threat_id = "2147917953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {08 94 13 09 11 04 11 09 19 5a 11 09 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 11 08 17 58 13 08}  //weight: 3, accuracy: High
        $x_1_2 = "Mariusz Komorowski" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NJ_2147917953_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NJ!MTB"
        threat_id = "2147917953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {06 8d 5d 00 00 01 0b 16 72 01 00 00 70 72 01 00 00 70 07 06 02 7b 5b 00 00 04 28 0e 01 00 06 0c 08 06 18 59 fe 04 0d 09 13 04 11 04 2c 03 00 2b 07 06 18 5a 0a}  //weight: 3, accuracy: High
        $x_2_2 = {28 3f 00 00 0a 07 16 08 08 16 30 03 16 2b 01 17 59 6f 00 01 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NJ_2147917953_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NJ!MTB"
        threat_id = "2147917953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {73 a3 00 00 0a 0a 28 e3 01 00 06 0b 07 1f 20 8d 58 00 00 01 25 d0 6a 02 00 04 28 8b 00 00 0a 6f c8 00 00 0a 07 1f 10 8d 58 00 00 01 25 d0 6c 02 00 04 28 8b 00 00 0a 6f c9 00 00 0a}  //weight: 3, accuracy: High
        $x_2_2 = {6f ca 00 00 0a 17 73 a4 00 00 0a 25 02 16 02 8e 69 6f a5 00 00 0a 6f a8 00 00 0a 06 6f a7 00 00 0a}  //weight: 2, accuracy: High
        $x_1_3 = "set_ClientCredential" ascii //weight: 1
        $x_1_4 = "WindowsApplication11.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NJ_2147917953_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NJ!MTB"
        threat_id = "2147917953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {07 6f 23 00 00 0a a5 19 00 00 01 0c 12 02 28 24 00 00 0a 6f 25 00 00 0a 0d 12 02 28 26 00 00 0a 13 04 11 04 75 01 00 00 1b 2c 5a 11 04 74 01 00 00 1b 13 05 09 72 3b 00 00 70 1b 6f 27 00 00 0a 2c 15 06 09 72 4d 00 00 70 28 28 00 00 0a 28 1b 00 00 0a 13 06 2b 1c 09 28 29 00 00 0a 13 07 06 11 07 72 57 00 00 70 28 28 00 00 0a 28 1b 00 00 0a 13 06 11 06 28 1c 00 00 0a 2d 09 11 06 11 05 28 2a 00 00 0a 07 6f 2b 00 00 0a 3a 70 ff ff ff}  //weight: 3, accuracy: High
        $x_2_2 = {6f 2d 00 00 06 6f 3d 00 00 0a 25 03 6f 31 00 00 06 25 03 28 3e 00 00 0a 6f 34 00 00 06 6f 36 00 00 06 de 19}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NJ_2147917953_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NJ!MTB"
        threat_id = "2147917953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 55 00 00 70 6f ?? 00 00 0a 00 25 72 65 00 00 70 11 04 72 cf 00 00 70 28 28 00 00 0a 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 17}  //weight: 3, accuracy: Low
        $x_1_2 = "trojam.Properties.Resources" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Jalapeno_TMAA_2147917980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.TMAA!MTB"
        threat_id = "2147917980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 59 91 61 ?? 08 20 0d 02 00 00 58 20 0c 02 00 00 59 1d 59 1d 58 ?? 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BZ_2147918059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BZ!MTB"
        threat_id = "2147918059"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptedFile.exe" ascii //weight: 1
        $x_1_2 = "Soraadd.Resources" ascii //weight: 1
        $x_1_3 = "SoraAdd.exe" ascii //weight: 1
        $x_1_4 = "36537493-e85c-4d7e-96bc-32c472e96b4c" ascii //weight: 1
        $x_1_5 = "7c23ff90-33af-11d3-95da-00a024a85b51" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NF_2147919249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NF!MTB"
        threat_id = "2147919249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1f 0b 11 26 58 1d 11 22 58 61 d2 13 1a}  //weight: 2, accuracy: High
        $x_1_2 = {11 19 18 91 11 19 19 91 1f 10 62 60 11 19 16 91 1e 62 60 11 19 17 91 1f 18 62 60 02 65 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NF_2147919249_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NF!MTB"
        threat_id = "2147919249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {02 6f 0f 00 00 0a 0a 20 5e 1d 44 4c 03 58 20 24 00 00 00 d3}  //weight: 3, accuracy: High
        $x_2_2 = {5f 07 25 17 58 0b 61 d2 0d 25 1e 63 07 25 17 58 0b 61 d2}  //weight: 2, accuracy: High
        $x_1_3 = "ContainsKey" ascii //weight: 1
        $x_1_4 = "49CC6B38-355C-4F68-BFDC-1205742F5A93" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ULAA_2147919544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ULAA!MTB"
        threat_id = "2147919544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 04 08 20 0c 02 00 00 58 20 0b 02 00 00 59 1b 59 1b 58 04 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_UTAA_2147919833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.UTAA!MTB"
        threat_id = "2147919833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 08 20 0c 02 00 00 58 20 0b 02 00 00 59 1b 59 1b 58 03 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_VEAA_2147920050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.VEAA!MTB"
        threat_id = "2147920050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 1b 12 05 2b 1b 08 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 1d 11 04 2b e1 28 ?? 00 00 0a 2b de 1e 2c 0b 11 05 2c 07 11 04 28 ?? 00 00 0a 1c 2c f6 dc 17 2c bd 09 18 25 2c 09 58 0d 09 07 6f ?? 00 00 0a 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_XMAA_2147921703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.XMAA!MTB"
        threat_id = "2147921703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 05 2a 00 11 00 72 97 00 00 70 28 ?? 00 00 06 72 c9 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 09 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? 00 00 00 26}  //weight: 3, accuracy: Low
        $x_2_2 = {11 03 11 07 16 11 07 8e 69 28 ?? 00 00 06 20}  //weight: 2, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GetByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_XRAA_2147921705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.XRAA!MTB"
        threat_id = "2147921705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 13 04 2b 28 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? 00 00 0a 17 59 33 04 16 0d 2b 04 09 17 58 0d 11 04 17 58 13 04 11 04 02 8e 69 32 d1}  //weight: 3, accuracy: Low
        $x_2_2 = {02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 8d ?? 00 00 01 0c 16 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SK_2147921710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SK!MTB"
        threat_id = "2147921710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 72 15 00 00 70 6f 29 00 00 0a 0a dd 0d 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SARA_2147921756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SARA!MTB"
        threat_id = "2147921756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d1 13 14 11 1d 11 09 91 13 22 11 1d 11 09 11 22 11 21 61 11 1f 19 58 61 11 34 61 d2 9c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AMB_2147921788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AMB!MTB"
        threat_id = "2147921788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 08 06 07 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 10 00 dd ?? 00 00 00 11 05 39 ?? 00 00 00 11 05 6f ?? 00 00 0a dc 11 04 39}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_VV_2147921878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.VV!MTB"
        threat_id = "2147921878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 33 00 00 0a 80 01 00 00 04 73 34 00 00 0a 80 02 00 00 04 73 35 00 00 0a 80 03 00 00 04 73 35 00 00 0a 80 04 00 00 04 7e 03 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_MBXT_2147922236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.MBXT!MTB"
        threat_id = "2147922236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 31 37 44 31 35 00 34 35 42 37 37 43 31 38 00 46 30 33 46 35 30}  //weight: 2, accuracy: High
        $x_1_2 = "16B7C39A.resources" ascii //weight: 1
        $x_1_3 = "unknownspf_loader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_YJAA_2147922431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.YJAA!MTB"
        threat_id = "2147922431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 04 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 05 11 05 6f ?? 01 00 0a 11 05 6f ?? 01 00 0a 6f ?? 01 00 0a 13 06 11 06 02 74 ?? 00 00 1b 16 02 14 72 1e 2c 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 01 00 0a 0b 07 74 ?? 00 00 1b 28 ?? 01 00 06 14 72 44 2c 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 74 ?? 00 00 1b 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SL_2147922694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SL!MTB"
        threat_id = "2147922694"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$675282ac-a345-491b-9292-f1e54d17c1cc" ascii //weight: 2
        $x_2_2 = "Lab06_Bai01" ascii //weight: 2
        $x_2_3 = "Control_Viewer.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SM_2147922696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SM!MTB"
        threat_id = "2147922696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 06 07 07 18 5a 9e 00 07 17 58 0b 07 20 e8 03 00 00 fe 04 0c 08 2d e8}  //weight: 2, accuracy: High
        $x_1_2 = "$5ec208b3-0188-4bc1-9cc3-0bfa6e6f2c39" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NG_2147922727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NG!MTB"
        threat_id = "2147922727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 11 0c 25 17 58 13 0c 11 0b 1e 64 d2 9c}  //weight: 2, accuracy: High
        $x_1_2 = {11 03 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_VGV_2147922955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.VGV!MTB"
        threat_id = "2147922955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 11 06 7e 01 00 00 04 11 06 91 20 82 00 00 00 61 d2 9c 11 06 17 58 13 06 20 0f 00 68 33 fe 0e 0a 00 fe 0d 0a 00 00 48 68 d3 13 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AS_2147923705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AS!MTB"
        threat_id = "2147923705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 72 c9 00 00 70 15 16 28 5b 00 00 0a 0b 19 08 72 ef 00 00 70 07 19 9a 28 ?? 00 00 0a 1f 20 19 15 15 28 ?? 00 00 0a 19 07 17 9a 21 ff ff ff ff ff ff ff ff 16 28 ?? 00 00 0a 17 8d 26 00 00 01 0d 09 16 19 9e 09 28 ?? 00 00 0a 19 08 72 ef 00 00 70 07 1a 9a 28 ?? 00 00 0a 1f 20 19 15 15 28 ?? 00 00 0a 19 07 18 9a 21 ff ff ff ff ff ff ff ff 16 28 ?? 00 00 0a 17 8d 26 00 00 01 0d 09 16 19 9e 09 28 ?? 00 00 0a 08 07 19 9a 28 ?? 00 00 0a 28 ?? 00 00 0a 26 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SN_2147923794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SN!MTB"
        threat_id = "2147923794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8ae50c39.Resources.resources" ascii //weight: 1
        $x_1_2 = "$d2d22a78-cd4e-4d99-a9de-306d662558b5" ascii //weight: 1
        $x_1_3 = "ProDRENALIN.exe" ascii //weight: 1
        $x_1_4 = "proDAD 2013-2017" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_GM_2147923800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.GM!MTB"
        threat_id = "2147923800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 28 11 00 00 0a 20 00 f2 2b 00}  //weight: 1, accuracy: High
        $x_1_2 = {80 01 00 00 04 73 36 00 00 0a 80 02 00 00 04 73 37 00 00 0a 80 03 00 00 04 73 37 00 00 0a 80 04 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ADBA_2147924124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ADBA!MTB"
        threat_id = "2147924124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b 3b 2b 40 2b 45 72 ?? ?? 03 70 2b 45 2b 4a 1d 2c 07 2b 48 14 2b 48 2c 03 2b 4b 7a 16 2d f0 17 2c ed d0 ?? 00 00 01 2b 44 06 72 ?? ?? 03 70 28 ?? 00 00 0a 80 ?? 00 00 04 16 2d d3 2a 28 ?? 00 00 0a 2b be 28 ?? ?? 00 06 2b b9 6f ?? 00 00 0a 2b b4 6f ?? 00 00 0a 2b b4 0a 2b b3 06 2b b5 28 ?? 00 00 0a 2b b1}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ARAX_2147924449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ARAX!MTB"
        threat_id = "2147924449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 18 07 11 18 93 66 d1 9d 11 18 17 58 13 18 11 18 07 8e 69 32 e9}  //weight: 2, accuracy: High
        $x_2_2 = {07 11 12 07 11 12 93 66 d1 9d 11 12 17 58 13 12 11 12 07 8e 69 32 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Jalapeno_NK_2147924509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NK!MTB"
        threat_id = "2147924509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {28 21 00 00 0a 13 09 11 09 28 03 00 00 06 11 09 14 fe 06 09 00 00 06 73 29 00 00 0a 28 08 00 00 06}  //weight: 3, accuracy: High
        $x_1_2 = "AfhostRandomFolder" ascii //weight: 1
        $x_1_3 = "MicrosoftEdge.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AJA_2147924828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AJA!MTB"
        threat_id = "2147924828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {16 13 07 2b 12 00 11 06 11 07 58 05 11 07 91 52 00 11 07 17 58 13 07 11 07 05 8e 69 fe 04 13 08 11 08 2d e1}  //weight: 3, accuracy: High
        $x_2_2 = {16 13 09 2b 24 00 06 11 07 11 09 58 91 07 11 09 91 fe 01 16 fe 01 13 0a 11 0a 2c 06 00 16 13 08 2b 14 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0b 11 0b 2d cf 11 08 13 0c 11 0c 2c 0b 00 08 11 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_VG_2147924830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.VG!MTB"
        threat_id = "2147924830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 05 7e ?? 00 00 04 11 05 91 20 82 00 00 00 61 d2 9c 11 05 17 58 13 05 20 ?? ?? ?? ?? 00 fe 0e [0-6] fe 0d 09 [0-4] 48 68 d3 13 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ACCA_2147924914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ACCA!MTB"
        threat_id = "2147924914"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {38 d4 00 00 00 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 1c 2c ed 17 2c ea 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 1e 2b 20 16 07 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 28 ?? 00 00 0a 13 06 1c 2c e2 de 32 11 05 2b de 07 2b dd}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AJCA_2147925102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AJCA!MTB"
        threat_id = "2147925102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 26 06 72 f7 01 00 70 18 18 8d ?? 00 00 01 25 16 04 a2 25 17 05 a2 28 ?? 00 00 0a 0b 03 73 ?? 00 00 0a 0c 08 07 74 ?? 00 00 01 16 73 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 00 09 11 04 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 05 de 23}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 26 06 72 d9 01 00 70 1e 17 8d ?? 00 00 01 25 16 04 a2 28 ?? 00 00 0a 26 06 72 e9 01 00 70 1e 17 8d ?? 00 00 01 25 16 05 a2}  //weight: 2, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_MBXW_2147925128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.MBXW!MTB"
        threat_id = "2147925128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {20 79 01 00 00 91 1f 45 58 13 17}  //weight: 3, accuracy: High
        $x_2_2 = "FinalProjectForNETD" ascii //weight: 2
        $x_1_3 = "063c10458dd7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AMY_2147925623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AMY!MTB"
        threat_id = "2147925623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "DDrLe9PDDDsyfDDDFk\\rLzDDFke.DV3FIlrKe9TDDDrOFJ" wide //weight: 4
        $x_1_2 = "kH7H}TUQETXI73vDDDEH}nURU\\[qEH8I" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SZDF_2147925747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SZDF!MTB"
        threat_id = "2147925747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 05 11 04 11 06 1f 1f 5f 62 60 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 00 08 6f ?? 00 00 0a 13 0f 2b 00 11 0f 2a}  //weight: 5, accuracy: Low
        $x_4_2 = {08 11 05 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 11 05 1e 63 13 05 11 06 1e 59 13 06 00 11 06 1d fe 02 13 0c 11 0c 2d d7}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AUCA_2147925822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AUCA!MTB"
        threat_id = "2147925822"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lwe understand understand galaxy support large communicate network teach grow" ascii //weight: 2
        $x_2_2 = "quick vision slow white organize" ascii //weight: 2
        $x_2_3 = "lead inspire change" ascii //weight: 2
        $x_2_4 = "direct small direct" ascii //weight: 2
        $x_1_5 = "us collaborate connect" ascii //weight: 1
        $x_1_6 = "support green you" ascii //weight: 1
        $x_1_7 = "$548acdbc-fce2-4d83-aa05-7b61ca75b9be" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_PMOH_2147926033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.PMOH!MTB"
        threat_id = "2147926033"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {00 02 04 05 28 ?? 00 00 06 0a 0e 04 03 6f ?? 00 00 0a 59 0b 03 06 07 28 ?? 00 00 06 00 2a}  //weight: 9, accuracy: Low
        $x_1_2 = {4c 00 6f 00 61 00 64 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AYA_2147926813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AYA!MTB"
        threat_id = "2147926813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Thread_hijacking" ascii //weight: 2
        $x_1_2 = "$009ab3ac-373b-4ddb-a8f3-5A50D13265EA" ascii //weight: 1
        $x_1_3 = "TheAttack.exe" ascii //weight: 1
        $x_1_4 = "ProcessInject" ascii //weight: 1
        $x_1_5 = "Successfully created the process..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NIT_2147926893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NIT!MTB"
        threat_id = "2147926893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 00 28 1e 00 00 0a 7d 04 00 00 04 12 00 15 7d 03 00 00 04 12 00 7b 04 00 00 04 0b 12 01 12 00 28 ?? 00 00 2b 12 00 7c 04 00 00 04 28 ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {20 00 0c 00 00 28 ?? 00 00 0a 7e 01 00 00 04 28 ?? 00 00 06 6f ?? 00 00 0a 0a 12 00 28 ?? 00 00 0a 28 ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NIT_2147926893_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NIT!MTB"
        threat_id = "2147926893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 27 00 00 0a 20 e8 03 00 00 20 88 13 00 00 6f 28 00 00 0a 28 21 00 00 0a 7e 0f 00 00 04 2d 0a 28 1e 00 00 06 28 18 00 00 06 7e 16 00 00 04 6f 29 00 00 0a 26 17 2d c8}  //weight: 2, accuracy: High
        $x_1_2 = "capCreateCaptureWindowA" ascii //weight: 1
        $x_1_3 = "capGetDriverDescriptionA" ascii //weight: 1
        $x_1_4 = "Antivirus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Jalapeno_NIT_2147926893_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NIT!MTB"
        threat_id = "2147926893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 03 08 03 6f 07 00 00 0a 5d 17 d6 17 28 ?? 00 00 0a 28 ?? 00 00 0a da 13 04 06 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 08 17 d6 0c 00 08 09 fe 02 16 fe 01 13 05 11 05 2d b5}  //weight: 2, accuracy: Low
        $x_1_2 = {a2 00 11 0a 28 ?? 00 00 0a 07 28 ?? 00 00 06 28 ?? 00 00 0a 13 09 11 09 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 13 08 11 08 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NIT_2147926893_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NIT!MTB"
        threat_id = "2147926893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 28 df 03 00 0a 00 28 ?? 03 00 06 80 4f 00 00 0a 28 ?? 05 00 06 6f 00 06 00 06 80 1a 03 00 0a 28 ?? 05 00 06 6f 02 06 00 06 72 77 03 00 70 28 ?? 00 00 0a 16 fe 01 0b 07 2d 1b 00 28 ?? 05 00 06 6f 02 06 00 06 72 17 22 00 70 28 ?? 01 00 0a 80 10 02 00 0a 00 16 28 ?? 03 00 0a 00 73 df 00 00 06 0a 06 6f e2 00 00 0a 17 fe 01 16 fe 01 0b 07 2d 0b 73 89 02 00 06 28 ?? 03 00 0a 00 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "DecryptString" ascii //weight: 1
        $x_1_3 = "DecryptDES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NIT_2147926893_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NIT!MTB"
        threat_id = "2147926893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {12 00 12 01 28 02 00 00 06 07 28 01 00 00 0a 0c 7e 05 00 00 04 0d 08 7e 06 00 00 04 6f 02 00 00 0a 13 04 11 04 14 28 03 00 00 0a 39 01 00 00 00 2a 11 04 09 6f 04 00 00 0a 13 05 11 05 14 28 05 00 00 0a 39 01 00 00 00 2a 11 05 14 18 8d 04 00 00 01 13 06 11 06 16 28 06 00 00 0a a2 11 06 17 06 28 04 00 00 06 a2 11 06 6f 07 00 00 0a 26 2a}  //weight: 2, accuracy: High
        $x_1_2 = {1e 8d 0a 00 00 01 0c 07 28 0a 00 00 0a 03 6f 0b 00 00 0a 6f 0c 00 00 0a 0d 09 16 08 16 1e 28 0d 00 00 0a 06 08 6f 0e 00 00 0a 06 18 6f 0f 00 00 0a 06 18 6f 10 00 00 0a 06 6f 11 00 00 0a 13 04 02 28 12 00 00 0a 13 05 11 04 11 05 16 11 05 8e 69 6f 13 00 00 0a 13 06 28 0a 00 00 0a 11 06 6f 14 00 00 0a 13 07 dd 0d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_MX_2147927894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.MX!MTB"
        threat_id = "2147927894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 1a 8d 3a 00 00 01 25 16 72 71 00 00 70 a2 25 17 72 c9 00 00 70 a2 25 18 72 1b 01 00 70 a2 25 19 72 73 01 00 70 a2 7d 08 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AVGA_2147928707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AVGA!MTB"
        threat_id = "2147928707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 04 02 11 04 91 07 11 04 07 8e b7 5d 91 61 09 11 04 09 8e b7 5d 91 61 9c 7e ?? 00 00 04 1f 1c 94 fe ?? ?? 00 00 01 58 7e ?? 00 00 04 1f 1d 94 59 13 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SKKP_2147929581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SKKP!MTB"
        threat_id = "2147929581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 8e 69 20 00 30 00 00 1f 40 28 ?? 00 00 06 0a 02 16 06 02 8e 69 28 ?? 00 00 0a 7e 04 00 00 0a 0b 7e 04 00 00 0a 26 16 73 06 00 00 0a 26 16 73 06 00 00 0a 26 06 0c 7e 04 00 00 0a 16 08 7e 04 00 00 0a 16 7e 04 00 00 0a 28 ?? 00 00 06 0b 07 15 28 ?? 00 00 06 26 2a}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AWHA_2147929683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AWHA!MTB"
        threat_id = "2147929683"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 00 08 07 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0d 00 14 13 04 02 8e 69 17 58 8d ?? 00 00 01 13 04 16 13 05 09 11 04 16 02 8e 69 6f ?? 00 00 0a 13 05 11 05 17 58 8d ?? 00 00 01 0a 11 04 06 11 05 28 ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 00 de 12}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ABIA_2147929799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ABIA!MTB"
        threat_id = "2147929799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 11 04 09 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 08 16 08 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 25 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 dd}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_GNT_2147929902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.GNT!MTB"
        threat_id = "2147929902"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 08 1a 8d ?? ?? ?? ?? 13 09 11 08 11 09 16 1a 6f ?? ?? ?? 0a 26 11 09 16 28 ?? ?? ?? 0a 13 0a 11 08 16 73 ?? ?? ?? 0a 13 0b 11 0b 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ARAZ_2147932553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ARAZ!MTB"
        threat_id = "2147932553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 06 02 06 91 08 08 11 04 84 95 08 11 07 84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 61 86 9c 18 38 78 ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ABLA_2147933277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ABLA!MTB"
        threat_id = "2147933277"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b 2c 2b 2d 2b 2e 08 07 6f ?? 04 00 0a 08 6f ?? 04 00 0a 0d 73 ?? 04 00 0a 25 09 02 16 02 8e 69 6f ?? 03 00 0a 6f ?? 04 00 0a 13 04 de 1a 08 2b d1 06 2b d0 6f ?? 04 00 0a 2b cb}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AQLA_2147933687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AQLA!MTB"
        threat_id = "2147933687"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 25 16 0f 00 20 09 02 00 00 20 42 02 00 00 28 ?? 00 00 06 9c 25 17 0f 00 20 9a 00 00 00 20 d6 00 00 00 28 ?? 00 00 06 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 2a d0 34 00 00 06 26 2a}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 0f 00 20 59 01 00 00 20 12 01 00 00 28 ?? 00 00 06 9c 25 17 0f 00 20 da 01 00 00 20 96 01 00 00 28 ?? 00 00 06 9c 25 18 0f 00 20 18 03 00 00 20 55 03 00 00 28 ?? 00 00 06 9c 0a 1d 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ATLA_2147933774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ATLA!MTB"
        threat_id = "2147933774"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 1a 58 1a 59 91 61 03 08 20 10 02 00 00 58 20 0f 02 00 00 59 19 59 19 58 03 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_EAJF_2147935743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.EAJF!MTB"
        threat_id = "2147935743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 09 28 28 00 00 0a 07 6f 29 00 00 0a 1e 5b 8d 3e 00 00 01 13 04 1e 11 04 16 1e 28 2a 00 00 0a 73 2b 00 00 0a 13 05 04 07 08 11 04 6f 2c 00 00 0a 16 73 2d 00 00 0a 13 06 11 06 11 05 28 39 01 00 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_EAJF_2147935743_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.EAJF!MTB"
        threat_id = "2147935743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 02 6f 1f 00 00 0a 28 20 00 00 0a 0c 02 16 08 6f 21 00 00 0a 0d 09 1f 0a 6f 22 00 00 0a 13 04 11 04 16 31 0e 08 07 33 0a 09 16 11 04 6f 21 00 00 0a 0d 06 09 6f 23 00 00 0a 6f 24 00 00 0a 02 09 6f 1f 00 00 0a 6f 25 00 00 0a 6f 26 00 00 0a 10 00 02 6f 1f 00 00 0a 16 30 a5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_PWA_2147935794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.PWA!MTB"
        threat_id = "2147935794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 22 c3 f5 48 40 6f ?? 00 00 0a 26 2b 64 00 73 ac 00 00 0a 13 05 11 05 07 6f ?? 00 00 0a 26 11 05 07 6f ?? 00 00 0a 26 73 af 00 00 0a 13 06 11 06 72 c3 08 00 70 6f ?? 00 00 0a 00 11 06 6f ?? 00 00 0a 26 02 09 03 04 28 ?? 00 00 06 00 73 b2 00 00 0a 25 23 b6 f3 fd d4 41 4c 12 41 6f ?? 00 00 0a 00 13 07 11 07 6f ?? 00 00 0a 00 09 17 58 0d 00 09 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 08 11 08 2d 81}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_A_2147935980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.A!MTB"
        threat_id = "2147935980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 00 40 01 00 8d 84 00 00 01 0a 38 09 00 00 00 03 06 16 07 6f 26 01 00 0a 02 06 16 06 8e 69 6f 27 01 00 0a 25 0b 3a e5 ff ff ff}  //weight: 5, accuracy: High
        $x_2_2 = {8d 84 00 00 01 0d 73 da 00 00 0a 09 ?? ?? ?? ?? ?? 08 8e 69 09 8e 69 58 8d 84 00 00 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ZHA_2147936058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ZHA!MTB"
        threat_id = "2147936058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 17 58 0a 08 07 6f ?? 00 00 0a 06 17 58 0a 73 ?? 00 00 0a 0d 06 17 58 0a 09 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 06 17 58 0a 11 04 02 1f 10 02 8e 69 1f 10 59 6f ?? 00 00 0a 06 17 58 0a 11 04}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AC_2147936270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AC!MTB"
        threat_id = "2147936270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1f 28 28 11 00 00 0a 72 01 00 00 70 02 72 15 00 00 70 28 12 00 00 0a 73 13 00 00 0a 0a 73 14 00 00 0a 0b ?? ?? 06 03 2d 07 72 43 00 00 70 2b 05 72 4f 00 00 70}  //weight: 2, accuracy: Low
        $x_1_2 = "a19069bb-bd9a-4ca8-b8eb-5862dda44c02" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AH_2147936279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AH!MTB"
        threat_id = "2147936279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 0c 07 08 16 1a 6f 3f 00 00 0a 26 08 16 28 45 00 00 0a 26 07 16 73 46 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SDGB_2147936301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SDGB!MTB"
        threat_id = "2147936301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 08 20 ?? ?? ?? 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 08 20 ?? ?? ?? 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 28 ?? 00 00 0a 09 07 16 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0a de 0a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AI_2147936816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AI!MTB"
        threat_id = "2147936816"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 0a 06 16 06 8e 69 6f 1a 00 00 0a 26 28 1b 00 00 0a 0b 07 28 1c 00 00 0a}  //weight: 2, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "get_G" ascii //weight: 1
        $x_1_4 = "CompressionMode" ascii //weight: 1
        $x_1_5 = "GZipStream" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AJ_2147936817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AJ!MTB"
        threat_id = "2147936817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 7d 92 01 00 04 16 0a 02 7b 93 01 00 04 16 12 00 28 46 02 00 0a 06 2c 0e 04 02 7b 92 01 00 04}  //weight: 2, accuracy: High
        $x_2_2 = "Umbral Stealer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AK_2147936818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AK!MTB"
        threat_id = "2147936818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 13 04 16 13 08 2b 26 11 07 11 05 11 08 1a 11 04 16 6f 5d 00 00 0a 26 11 08 1a d6 13 08 08 11 04 16 11 07 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_PLJAH_2147937033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.PLJAH!MTB"
        threat_id = "2147937033"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 00 06 6f ?? 00 00 0a 0b 07 03 16 03 8e 69 6f ?? 00 00 0a 0c 08 13 05 2b 00 11 05 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SJDA_2147937140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SJDA!MTB"
        threat_id = "2147937140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 2b 28 72 ?? ?? 00 70 2b 24 2b 29 2b 2e 72 ?? ?? 00 70 2b 2a 2b 2f 1a 2c f2 2b 31 2b 32 06 16 06 8e 69 6f ?? 00 00 0a 0c de 47 07 2b d5 28 ?? 00 00 0a 2b d5 6f ?? 00 00 0a 2b d0 07 2b cf 28 ?? 00 00 0a 2b cf 6f ?? 00 00 0a 2b ca 07 2b cc 6f ?? 00 00 0a 2b c7 07 2c 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ANV_2147937598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ANV!MTB"
        threat_id = "2147937598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {28 03 00 00 06 0c 72 61 00 00 70 28 01 00 00 0a 0d 72 93 00 00 70 28 01 00 00 0a 13 04 73 02 00 00 0a 13 05 73 03 00 00 0a 13 06 11 06 11 05 09 11 04 6f 04 00 00 0a 17 73 05 00 00 0a 13 07 11 07 08 16 08 8e 69 6f 06 00 00 0a 17 0b 11 06 6f 07 00 00 0a 13 08 dd 43 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_MBV_2147938049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.MBV!MTB"
        threat_id = "2147938049"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 2b 16 95 11 2a 20 32 09 00 00 95 58 e0 91 11 2a 20 29 0f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AM_2147939498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AM!MTB"
        threat_id = "2147939498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 25 17 28 18 00 00 06 13 04 06 28 13 00 00 06 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 6f}  //weight: 2, accuracy: High
        $x_1_2 = "server1" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AN_2147939504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AN!MTB"
        threat_id = "2147939504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 0d 28 5b 00 00 0a 09 6f 5c 00 00 0a 07 1f 7d 30 10 08 20 80 00 00 00 07 60 d2 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_PGJ_2147939896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.PGJ!MTB"
        threat_id = "2147939896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 02 7b 05 00 00 04 08 9a 7d 06 00 00 04 02 03 28 ?? 00 00 06 0d 02 7b 09 00 00 04 09 72 01 00 00 70 6f ?? 00 00 0a 0b 07 72 01 00 00 70 28 ?? 00 00 0a 2c 07 07 28 ?? 00 00 2b 2a 08 17 58 0c 08 02 7b 05 00 00 04 8e 69 32 b5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_PGJ_2147939896_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.PGJ!MTB"
        threat_id = "2147939896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {12 00 12 01 28 ?? 00 00 06 02 06 07 28 ?? 00 00 06 51 28 ?? 00 00 06 0c 03 08 28 ?? 00 00 06 51 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "jYD4qT79ijWbcPokxlX7kiHdzr+mqTdPtAORkQe04MRlvMFR0YUgI7QDkZEHtODE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_PGJ_2147939896_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.PGJ!MTB"
        threat_id = "2147939896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 69 00 72 00 6f 00 73 00 61 00 76 00 76 00 61 00 2d 00 63 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f}  //weight: 1, accuracy: High
        $x_4_2 = "cmVmZXJyZXI9ZnJlZS1kb3dubG9hZCZnYWRfc291cmNlPTEmZ2NsaWQ9RUFJYUlRb2JDaE1JN3F6VG85X01pd01WUFVMX0FSMWdyQWNTRUFBWUFTQUFFZ0xHTGZEX0J3RQ==" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AVN_2147940696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AVN!MTB"
        threat_id = "2147940696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 28 2a 00 00 0a 0a 28 2b 00 00 0a 06 6f 2c 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_2_2 = {03 28 42 00 00 0a 0b 06 16 73 43 00 00 0a 0c 08 07 6f 44 00 00 0a 20 a0 86 01 00 28 45 00 00 0a de 1e}  //weight: 2, accuracy: High
        $x_2_3 = {02 6f 28 00 00 0a 0a 16 0b 2b 0d 06 07 06 07 93 1b 59 d1 9d 07 17 58 0b 07 06 8e 69 32 ed 06 73 29 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_2_4 = "$b0581b8b-743d-451d-8e83-09b32e19c247" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_JK_2147940697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.JK!MTB"
        threat_id = "2147940697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {06 02 28 0b 00 00 06 28 06 00 00 06 28 1f 00 00 0a 06 28 20 00 00 0a 26 28 1c 00 00 0a 72 29 00 00 70 28 1d 00 00 0a 0b 07 02 28 0c 00 00 06 28 06 00 00 06 28 1f 00 00 0a 07 28 20 00 00 0a 26 02 28 21 00 00 0a 2a}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ZRV_2147941501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ZRV!MTB"
        threat_id = "2147941501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1a 2c 5a 72 f9 00 00 70 38 8a 00 00 00 0d 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 72 13 01 00 70 13 06 11 05 06 16 06 8e 69 6f ?? 00 00 0a 13 07 11 06 03 11 07 28 ?? 00 00 06 de 0c}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SP_2147941903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SP!MTB"
        threat_id = "2147941903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69}  //weight: 2, accuracy: High
        $x_1_2 = "SharpEfsPotato.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_MKG_2147942010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.MKG!MTB"
        threat_id = "2147942010"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 8e 69 1a 3f b9 00 00 00 20 05 00 00 00 38 ba ff ff ff 72 4c 03 00 70 28 ?? 00 00 0a 13 09 20 08 00 00 00 38 a4 ff ff ff 28 ?? 00 00 0a 13 0b 20 02 00 00 00 38 93 ff ff ff 72 a6 03 00 70 28 ?? 00 00 0a 13 0e 20 01 00 00 00 7e 94 01 00 04 7b ae 01 00 04 3a 73 ff ff ff}  //weight: 5, accuracy: Low
        $x_4_2 = {11 05 11 0b 6f ?? 00 00 0a 17 73 23 00 00 0a 13 0c 20 00 00 00 00 7e 94 01 00 04 7b 6d 01 00 04 39 0f 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe 0c 0d 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AYUA_2147942074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AYUA!MTB"
        threat_id = "2147942074"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1b 16 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? ?? 00 0a 16 13 11 2b af 11 09 75 ?? 00 00 01 6f ?? ?? 00 0a 11 08 74 ?? 00 00 01 6f ?? ?? 00 0a 0d de 49}  //weight: 5, accuracy: Low
        $x_2_2 = {0a 11 04 74 ?? 00 00 01 20 80 00 00 00 6f ?? ?? 00 0a 1f 09 13 0d 2b 85 11 04 75 ?? 00 00 01 19 6f ?? ?? 00 0a 11 04 74 ?? 00 00 01 08 74 ?? 00 00 1b 6f ?? ?? 00 0a 1b 13 0d 38 ?? ff ff ff 11 04 74 ?? 00 00 01 08 74 ?? 00 00 1b 6f ?? ?? 00 0a 11 04 74 ?? 00 00 01 6f ?? ?? 00 0a 13 06 18 13 0d 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_MBZ_2147942299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.MBZ!MTB"
        threat_id = "2147942299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 8e 69 5d 91 61 d2 81 ?? ?? 00 01 11 08 17 58 13 08 11 08 11 06 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ZAS_2147944031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ZAS!MTB"
        threat_id = "2147944031"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 02 11 03 11 00 11 03 91 11 04 11 03 11 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20 08 00 00 00 38 ?? ff ff ff 11 03 11 00 8e 69 3c ?? ff ff ff 20 07 00 00 00 38 ?? ff ff ff 11 00 8e 69 8d ?? 00 00 01 13 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BAA_2147944113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BAA!MTB"
        threat_id = "2147944113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 06 11 05 94 58 08 11 05 94 58 20 00 01 00 00 5d 13 04 06 11 05 94 13 06 06 11 05 06 11 04 94 9e 06 11 04 11 06 9e 11 05 17 58 13 05 11 05 20 00 01 00 00 32 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BAD_2147944122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BAD!MTB"
        threat_id = "2147944122"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 03 11 01 ?? ?? 00 00 0a 38 00 00 00 00 dd 1e 00 00 00 11 03 39 11 00 00 00 38 00 00 00 00 11 03 ?? ?? 00 00 0a 38 00 00 00 00 dc 38 00 00 00 00 11 01 ?? ?? 00 00 0a 13 04 38 2b 00 00 00 11 00 11 02 16 1a ?? ?? 00 00 0a 1a 3b 0b 00 00 00 38 00 00 00 00 73 1c 00 00 0a 7a 11 00 16 73 1d 00 00 0a 13 03 38 95 ff ff ff dd 41 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_DB_2147944222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.DB!MTB"
        threat_id = "2147944222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "106"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Okqiczyic.Properties.Resources" ascii //weight: 100
        $x_1_2 = "Shrblc" ascii //weight: 1
        $x_1_3 = "Ayvigver" ascii //weight: 1
        $x_1_4 = "Oalglxuvxkt" ascii //weight: 1
        $x_1_5 = "Btfzdwuqw" ascii //weight: 1
        $x_1_6 = "w3wp.exe" ascii //weight: 1
        $x_1_7 = "aspnet_wp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AVXA_2147944883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AVXA!MTB"
        threat_id = "2147944883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 0a 00 00 0a 0a 06 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? 00 00 0a 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 02 28 ?? 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 08 13 05 de 14}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AX_2147944972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AX!MTB"
        threat_id = "2147944972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 09 08 07 5a 8d ?? ?? 00 01 13 0a 02 09 11 05 07 5a 08 5a 6a 58 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AY_2147944973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AY!MTB"
        threat_id = "2147944973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 25 16 03 d2 9c 0b 02 07 28 0c 00 00 2b 28 0d 00 00 2b 0c 08 10 00 02 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AZ_2147944974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AZ!MTB"
        threat_id = "2147944974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0b 1a 8d 06 00 00 01 0c 06 08 16 1a 6f 35 00 00 0a 1a 2e 06 73 54 00 00 0a 7a 06 16 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BA_2147944977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BA!MTB"
        threat_id = "2147944977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 0d 08 09 16 09 8e 69 6f 7a 00 00 0a 26 07 09 6f 7b 00 00 0a 00 08 07 6f 7c 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BC_2147944978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BC!MTB"
        threat_id = "2147944978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 2a 06 20 05 00 00 00 64 0a 02 06 20 8f 56 5b 65 60 0a 7b dd 01 00 04 b6 06 20 42 44 5f 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BD_2147944979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BD!MTB"
        threat_id = "2147944979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 13 0a 28 8a 01 00 06 7e 94 00 00 0a 28 98 00 00 0a 13 0e 7e 6a 00 00 04 28 2b 01 00 06 0a 14 0b 14 0c 14 0d 7e 89 00 00 04 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BF_2147944985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BF!MTB"
        threat_id = "2147944985"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 0d 08 09 16 09 8e 69 6f 23 00 00 0a 26 09 16 28 24 00 00 0a 13 04 08 16 73 25 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BG_2147944986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BG!MTB"
        threat_id = "2147944986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 6e 20 ff 00 00 00 6a 5f b7 95 03 50 7b 6c 00 00 04 1e 64 61 7d 6c 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BH_2147944991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BH!MTB"
        threat_id = "2147944991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 0a 38 09 00 00 00 03 06 16 07 6f 59 00 00 0a 02 06 16 06 8e 69 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BJ_2147944992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BJ!MTB"
        threat_id = "2147944992"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 06 1d 11 06 1d 95 11 02 1d 95 61 9e 38 b7 00 00 00 11 06 1f 0d 11 06 1f 0d 95 11 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BL_2147945000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BL!MTB"
        threat_id = "2147945000"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 02 72 d5 27 00 70 6f e9 00 00 0a 2c 3e 06 02 6f ea 00 00 0a 0b 07 16 73 eb 00 00 0a 0c 73 ec 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BM_2147945001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BM!MTB"
        threat_id = "2147945001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 39 01 00 04 20 ed e1 77 9c 20 a3 d1 43 a7 61 20 02 00 00 00 63 20 7f 4e ff 1e 61 7d 43 01 00 04 20 00 00 00 00 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BO_2147945003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BO!MTB"
        threat_id = "2147945003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 14 00 fe 0c 11 00 3b 30 00 00 00 fe 0c 0b 00 fe 0c 14 00 46 fe 0c 03 00 61 52 fe 0c 14 00 20 01 00 00 00 58 fe 0e 14 00 fe 0c 0b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BP_2147945012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BP!MTB"
        threat_id = "2147945012"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 58 20 12 d8 36 57 11 0b 20 1f 00 00 00 5f 62 13 0b 0a 11 0b 20 84 14 01 5f 5a 13 0b 11 06 20 a6 63 ad e9 11 0b 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BQ_2147945013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BQ!MTB"
        threat_id = "2147945013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 07 00 20 71 c8 34 2c 5a 20 37 d3 b1 53 61 2b 22 fe 0c 07 00 20 cd 4a e5 67 5a 20 3a 15 76 73 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BR_2147945018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BR!MTB"
        threat_id = "2147945018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 7d f4 02 00 04 20 22 00 00 00 38 ae fd ff ff 7e ed 02 00 04 20 5d 2e 59 4f 20 ec f0 a8 3c 61 20 d1 6b 59 d4 59 20 e0 72 98 9f 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BS_2147945019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BS!MTB"
        threat_id = "2147945019"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 13 05 1f fe 66 13 06 2b 8d 09 1f f8 65 19 63 33 5b 20 3e 93 c3 0d 20 3c 93 c3 0d 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BAF_2147945038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BAF!MTB"
        threat_id = "2147945038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1a 8d 04 00 00 01 13 02 38 23 00 00 00 73 0e 00 00 0a 7a 11 00 16 73 0f 00 00 0a 13 03 38 24 00 00 00 11 01 ?? ?? 00 00 0a 13 04 38 48 00 00 00 11 00 11 02 16 1a ?? ?? 00 00 0a 1a 3b d2 ff ff ff 38 c7 ff ff ff 00 11 03 11 01 ?? ?? 00 00 0a 38 00 00 00 00 dd c8 ff ff ff 11 03 39 11 00 00 00 38 00 00 00 00 11 03 ?? ?? 00 00 0a 38 00 00 00 00 dc 38 aa ff ff ff dd 37 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_MCF_2147945468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.MCF!MTB"
        threat_id = "2147945468"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 09 11 0a 11 07 11 0a 91 11 08 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 07 8e 69 fe 04 13 13 11 13 2d de}  //weight: 10, accuracy: High
        $x_1_2 = "RuntimeBroker" ascii //weight: 1
        $x_1_3 = "VirtualAllocEx" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AQ_2147945973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AQ!MTB"
        threat_id = "2147945973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 0c 7e 89 00 00 04 02 4a 08 16 07 28 47 00 00 0a 03 08 04 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AT_2147945987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AT!MTB"
        threat_id = "2147945987"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 10 00 12 01 02 8e 69 28 10 02 00 0a 7d f8 03 00 04 12 01 02 8e 69 7d f7 03 00 04 02 16 07 7b f8 03 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AU_2147945988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AU!MTB"
        threat_id = "2147945988"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 1f 0f 62 11 0a 75 cc 00 00 1b 11 0c 25 17 58 13 0c 93 11 05 61 60 13 07 1f 09 13 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_MOH_2147946119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.MOH!MTB"
        threat_id = "2147946119"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {04 1b 5d 2c 0d 09 1f 12 93 20 00 73 00 00 59 0c 2b cf 1b 2b fa 03 2b 07 03 20 c8 00 00 00 61 b4 0a 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_KK_2147948351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.KK!MTB"
        threat_id = "2147948351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {0f 00 7b 0e 00 00 04 20 00 00 00 40 5f 2d 03 16 2b 01 17 0a 0f 00 7b 0e 00 00 04 20 00 00 00 80 5f 2d 03 16 2b 01 17 0b 0f 00 7b 0e 00 00 04 20 00 00 00 20 5f 2d 03 16 2b 01 17 0c}  //weight: 20, accuracy: High
        $x_10_2 = {11 04 28 03 00 00 2b 13 07 11 05 28 04 00 00 2b 13 08 02 7b 01 00 00 04 11 07 28 1c 00 00 06 28 14 00 00 0a 13 09 11 09 03 28 15 00 00 0a 2c 42 11 08 12 03 7b 89 00 00 04 36 0b 72 7d 01 00 70 73 27 00 00 06 7a 02}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_GVA_2147949247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.GVA!MTB"
        threat_id = "2147949247"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 16 13 09 2b 1a 00 08 11 09 08 11 09 91 07 11 09 07 8e 69 5d 91 61 d2 9c 00 11 09 17 58 13 09 11 09 08 8e 69 fe 04 13 0a 11 0a 2d d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SLDV_2147949856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SLDV!MTB"
        threat_id = "2147949856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5a 13 04 02 7b 3a 00 00 04 17 19 6f 76 00 00 0a 6c 13 05 02 7b 39 00 00 04 73 ae 00 00 06 25 02 7b 3a 00 00 04 16 02 28 73 00 00 0a 0c 12 02 28 77 00 00 0a 6f 76 00 00 0a 6b 02 7b 3a 00 00 04 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BAC_2147951024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BAC!MTB"
        threat_id = "2147951024"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 02 7b 02 00 00 04 11 04 91 58 03 11 04 06 5d 91 58 20 00 01 00 00 5d 0b 02 11 04 07 ?? ?? ?? ?? ?? 00 00 11 04 17 58 13 04 11 04 20 00 01 00 00 fe 04 13 05 11 05 2d c6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ZQR_2147951200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ZQR!MTB"
        threat_id = "2147951200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 02 11 01 6f ?? 00 00 0a 38 ?? 00 00 00 11 02 6f ?? 00 00 0a 13 03 38 ?? 00 00 00 00 02 73 ?? 00 00 0a 13 04 38 ?? 00 00 00 00 11 04 11 03 16 73 ?? 00 00 0a 13 05 38 ?? 00 00 00 00 73 ?? 00 00 0a 13 06 38 ?? 00 00 00 00 11 05 11 06 6f ?? 00 00 0a 38 ?? 00 00 00 11 06 6f ?? 00 00 0a 13 07}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BT_2147951416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BT!MTB"
        threat_id = "2147951416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 3e 08 11 3e 6d 61 0c 08 20 c0 9d fa 88 06 58 07 58 61 0c 08 20 bb 6d 07 4d 06 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BU_2147951417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BU!MTB"
        threat_id = "2147951417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 74 6e fe 0c b9 00 6e 61 20 93 01 00 01 6a 5a 6d fe 0e b9 00 11 46 46 fe 0e b8 00 11 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BV_2147951422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BV!MTB"
        threat_id = "2147951422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 20 21 16 03 04 61 07 20 62 5b 87 5e 60 0b 02 07 20 21 69 01 32 5c 0b fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BW_2147951424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BW!MTB"
        threat_id = "2147951424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 25 16 11 25 9c 25 17 11 26 9c 25 18 11 27 9c 13 32 11 0b 20 e8 03 00 00 5d 20 e7 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BX_2147951425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BX!MTB"
        threat_id = "2147951425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 59 7e 23 00 00 04 1f 66 95 5f 7e 23 00 00 04 1f 1a 95 61 59 80 17 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BY_2147951426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BY!MTB"
        threat_id = "2147951426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0a 1a 8d 0b 00 00 01 0b 06 07 16 1a 6f 1d 00 00 0a 26 07 16 28 1c 00 00 0a 0c 06 16 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_CA_2147951427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.CA!MTB"
        threat_id = "2147951427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 40 08 11 40 6d 61 0c 08 20 1e f8 0d bd 06 59 07 59 61 0c 08 06 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_CB_2147951428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.CB!MTB"
        threat_id = "2147951428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 11 04 1f 19 62 61 13 04 11 0d 20 ee 09 c6 24 5a 20 c8 2c 31 c8 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_EAOC_2147951573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.EAOC!MTB"
        threat_id = "2147951573"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 06 06 06 5a d2 9c 06 17 58 0a 06 11 05 8e 69 fe 04 13 0d 11 0d 2d e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AHB_2147951792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.AHB!MTB"
        threat_id = "2147951792"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {25 17 6f 23 00 00 0a 25 16 6f 22 00 00 0a 28 25 00 00 0a 25 2d 03 26 2b 05 28 35 00 00 0a}  //weight: 50, accuracy: High
        $x_30_2 = "hater/cecho.exe" ascii //weight: 30
        $x_20_3 = "hater/land.zip" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SLFG_2147952156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SLFG!MTB"
        threat_id = "2147952156"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 28 13 00 00 0a 0a 1f 10 8d 17 00 00 01 0b 06 16 07 16 1f 10 28 14 00 00 0a 00 06 8e 69 1f 10 59 8d 17 00 00 01 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ZDN_2147952425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ZDN!MTB"
        threat_id = "2147952425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 1b 11 1c 1f 61 5a 61 13 1d 00 02 11 1a 11 1c 6f ?? 00 00 0a 13 1e 04 03 6f ?? 00 00 0a 59 13 1f 11 1f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SLBM_2147952767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SLBM!MTB"
        threat_id = "2147952767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1f 23 28 18 00 00 0a 72 0d 00 00 70 28 19 00 00 0a 0a 1f 23 28 18 00 00 0a 72 39 00 00 70 28 19 00 00 0a 0b 06 28 1a 00 00 0a 0c 08 2d 17 00 06 28 09 00 00 06 28 1b 00 00 0a 00 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_GVB_2147953009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.GVB!MTB"
        threat_id = "2147953009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://fuckyou.com/?hecker" wide //weight: 2
        $x_1_2 = "Created mutated copy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ZSN_2147953206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ZSN!MTB"
        threat_id = "2147953206"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 09 11 05 58 91 07 11 05 91 2e 05 16 13 04 2b 0d 11 05 17 58 13 05 11 05 07 8e 69 32 e2 11 04 2c 07 08 09 6f ?? 00 00 0a 09 17 58 0d 09 06 8e 69 07 8e 69 59 31 c1 02 16 31 5b 02 08 6f ?? 00 00 0a 30 52 08 02 17 59 6f ?? 00 00 0a 07 8e 69 58 13 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ABGB_2147953321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ABGB!MTB"
        threat_id = "2147953321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 08 8e b7 17 da 11 05 da 02 11 05 91 06 61 8c ?? 00 00 01 07 17 8d ?? 00 00 01 13 08 11 08 16 11 04 8c ?? 00 00 01 a2 11 08 14 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 9c 11 05 17 d6 13 05 11 05 11 07 31 b9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ZEM_2147954211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ZEM!MTB"
        threat_id = "2147954211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 06 72 01 00 00 70 28 ?? 00 00 0a 72 04 02 00 70 6f ?? 00 00 0a 1f 64 73 05 00 00 0a 1f 10 6f ?? 00 00 0a 28 ?? 00 00 0a 72 46 02 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 17 73 08 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_LM_2147955984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.LM!MTB"
        threat_id = "2147955984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {02 74 1e 00 00 01 6f a2 00 00 0a 28 a3 00 00 0a 39 11 00 00 00 02 74 1e 00 00 01 6f a2 00 00 0a 0a dd d3 00 00 00 dd 06 00 00 00 26 dd 00 00 00 00 00 02 74 1e 00 00 01 6f 92 00 00 0a 6f a4 00 00 0a 6f a5 00 00}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_ALB_2147956218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.ALB!MTB"
        threat_id = "2147956218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 8e 69 0b 16 0c 2b 27 06 08 8f ?? 00 00 01 25 71 ?? 00 00 01 72 ?? 00 00 70 08 1f 21 5d 6f ?? 00 00 0a d2 61 d2 81 ?? 00 00 01 08 17 58 0c 08 07 17 59 33 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_NKA_2147956855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.NKA!MTB"
        threat_id = "2147956855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "encryptedText" ascii //weight: 2
        $x_1_2 = "SELECT * FROM Win32_ComputerSystemProduct" ascii //weight: 1
        $x_1_3 = "9478c812-7c17-46b6-be8b-d04009701f53" ascii //weight: 1
        $x_1_4 = "SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionStatus = 2" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 47 00 75 00 69 00 6c 00 68 00 65 00 72 00 6d 00 65 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 5c 00 56 00 69 00 73 00 75 00 61 00 6c 00 20 00 53 00 74 00 75 00 64 00 69 00 6f 00 20 00 32 00 30 00 31 00 32 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 73 00 5c 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 5c 00 6f 00 62 00 6a 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-47] 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_7 = {43 3a 5c 55 73 65 72 73 5c 47 75 69 6c 68 65 72 6d 65 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 32 5c 50 72 6f 6a 65 63 74 73 5c 4c 61 75 6e 63 68 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c [0-47] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Jalapeno_LMA_2147958064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.LMA!MTB"
        threat_id = "2147958064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {72 b4 00 00 70 28 08 00 00 0a 26 de 03 26 de 00 2a}  //weight: 10, accuracy: High
        $x_20_2 = {72 01 00 00 70 72 b0 00 00 70 02 7b 02 00 00 04 28 06 00 00 0a 28 07 00 00 0a 26 de 03 26 de 00 2a}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_LMA_2147958064_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.LMA!MTB"
        threat_id = "2147958064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {2b 00 28 0c 00 00 0a 28 0d 00 00 0a 8c 11 00 00 01 72 ?? 00 00 70 28 0e 00 00 0a 28 0f 00 00 0a 0a 06 73 10 00 00 0a 0b 07 72 ?? 00 00 70 28 11 00 00 0a 73 12 00 00 0a 72 ?? 00 00 70 6f 13 00}  //weight: 20, accuracy: Low
        $x_10_2 = {de 2c 13 04 72 ?? 00 00 70 73 10 00 00 0a 13 05 11 05 11 04 6f 22 00 00 0a 6f 14 00 00 0a de 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_AMTB_2147958515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno!AMTB"
        threat_id = "2147958515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 01 00 00 70 80 01 00 00 04 72 5f 00 00 70 80 02 00 00 04 2a}  //weight: 2, accuracy: High
        $x_2_2 = {28 05 00 00 0a 0a 16 0b 2b 23 06 07 9a 0c 08 6f 06 00 00 0a 02 1b 6f 07 00 00 0a 2c 0c 08 6f 08 00 00 0a 6f 09 00 00 0a 2a 07 17 58 0b 07 06 8e 69 32 d7 14 2a}  //weight: 2, accuracy: High
        $x_2_3 = {12 00 28 0a 00 00 0a 7d 0d 00 00 04 12 00 15 7d 0c 00 00 04 12 00 7c 0d 00 00 04 12 00 28 02 00 00 2b 12 00 7c 0d 00 00 04 28 0c 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_2_4 = "AdminId" ascii //weight: 2
        $x_2_5 = "BotToken" ascii //weight: 2
        $x_2_6 = "userIp" ascii //weight: 2
        $x_2_7 = "peredoz.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BAG_2147958993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BAG!MTB"
        threat_id = "2147958993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 09 02 16 02 8e 69 6f ?? 00 00 0a 38 ?? 00 00 00 38 ?? 00 00 00 20 00 00 00 00 fe 0e 00 00 fe 0c 00 00 45 01 00 00 00 13 00 00 00 fe 0c 00 00 20 dc 03 00 00 3b e5 ff ff ff 38 00 00 00 00 11 01 6f ?? 00 00 0a 73 ?? 00 00 0a 13 03 38 ?? 00 00 00 11 09 6f ?? 00 00 0a 20 00 00 00 00 7e ?? 00 00 04 7b 51 00 00 04 3a b6 ff ff ff 26 20 02 00 00 00 38 ?? ff ff ff 00}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_SLWG_2147959008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.SLWG!MTB"
        threat_id = "2147959008"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1a 8d 08 00 00 01 13 04 20 ?? 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 1d 00 00 00 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_LMB_2147959144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.LMB!MTB"
        threat_id = "2147959144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {28 0c 00 00 0a 28 0d 00 00 0a 8c 11 00 00 01 72 01 00 00 70 28 0e 00 00 0a 28 0f 00 00 0a 0a 06 73 10 00 00 0a 0b 07 72 0b 00 00 70 28 11 00 00 0a 73 12 00 00 0a 72 43 00 00 70 6f 13 00 00 0a 6f 14 00 00 0a de 0a}  //weight: 20, accuracy: High
        $x_15_2 = {13 04 72 57 00 00 70 73 10 00 00 0a 13 05 11 05 11 04 6f 22 00 00 0a 6f 14 00 00 0a de 0c 11 05 2c 07 11 05 6f 15 00 00 0a dc}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jalapeno_BAK_2147959386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jalapeno.BAK!MTB"
        threat_id = "2147959386"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 11 02 16 02 8e 69 6f ?? 00 00 0a 38 ?? 00 00 00 38 ?? 00 00 00 20 00 00 00 00 fe 0e 0f 00 fe 0c 0f 00 45 01 00 00 00 13 00 00 00 fe 0c 0f 00 20 dc 03 00 00 3b e5 ff ff ff 38 00 00 00 00 11 0c 6f ?? 00 00 0a 73 10 00 00 0a 13 0d 38 ?? 00 00 00 11 11 6f ?? 00 00 0a 20 01 00 00 00 7e 27 00 00 04 7b 6e 00 00 04 39 b6 ff ff ff 26 20 00 00 00 00 38 ab ff ff ff 00}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

