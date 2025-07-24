rule Trojan_MSIL_SnakeLogger_PA_2147772457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.PA!MTB"
        threat_id = "2147772457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SNAKE-KEYLOGGER" ascii //weight: 1
        $x_1_2 = "S--------N--------A--------K--------E----------------MISNAKE-KEYLOGGERMI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_PB_2147773657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.PB!MTB"
        threat_id = "2147773657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PK11SDR_Decrypt" wide //weight: 1
        $x_1_2 = "\\discord\\Local Storage\\leveldb" wide //weight: 1
        $x_2_3 = "-------- Snake Keylogger --------" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_PB_2147773657_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.PB!MTB"
        threat_id = "2147773657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\I$s#$lT3ssl.exe" wide //weight: 1
        $x_1_2 = "Twice Baked Potatoes" wide //weight: 1
        $x_1_3 = "http://tempuri.org/SampleProductsDataSet.xsd" wide //weight: 1
        $x_1_4 = "$6d529811-80e9-4938-b015-f47e98aaa9d7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_EXF_2147824992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.EXF!MTB"
        threat_id = "2147824992"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 15 1f 10 5d 93 11 17 61 11 15 20 ff 00 00 00 5d d1 61 d1}  //weight: 1, accuracy: High
        $x_1_2 = {06 07 02 07 18 5a 18 ?? ?? ?? ?? ?? 1f 10 ?? ?? ?? ?? ?? 9c 07 17 58 0b}  //weight: 1, accuracy: Low
        $x_1_3 = "FuckMicrosoft123" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_EXH_2147825124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.EXH!MTB"
        threat_id = "2147825124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 02 07 18 5a 18 ?? ?? ?? ?? ?? 1f 10 ?? ?? ?? ?? ?? 9c 07 17 58 0b}  //weight: 1, accuracy: Low
        $x_1_2 = "FuckMicrosoft123" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_SPQ_2147841493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.SPQ!MTB"
        threat_id = "2147841493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 11 08 07 11 08 9a 1f 10 28 ?? ?? ?? 0a d2 9c 11 08 17 58 13 08 11 08 07 8e 69 fe 04 13 09 11 09 2d dd}  //weight: 4, accuracy: Low
        $x_1_2 = "DASHBDGIGHBIJADG" ascii //weight: 1
        $x_1_3 = "QuizDesktopApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_SPEA_2147841495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.SPEA!MTB"
        threat_id = "2147841495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {00 11 06 11 0a 11 05 11 0a 9a 1f 10 28 ?? ?? ?? 0a 9c 00 11 0a 17 58 13 0a 11 0a 11 05 8e 69 fe 04 13 0b 11 0b 2d d9}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_SPEAB_2147841496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.SPEAB!MTB"
        threat_id = "2147841496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 11 07 08 11 07 9a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 07 17 58 13 07 11 07 08 8e 69 fe 04 13 08 11 08 2d db}  //weight: 4, accuracy: Low
        $x_1_2 = "geq-c/p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_DAM_2147841513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.DAM!MTB"
        threat_id = "2147841513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 11 07 07 8e 69 5d 07 11 07 07 8e 69 5d 91 08 11 07 1f 16 5d 91 61 28 ?? 00 00 06 07 11 07 17 58 07 8e 69 5d 91 28 ?? 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_DAN_2147841530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.DAN!MTB"
        threat_id = "2147841530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0d 16 13 09 2b 16 09 11 09 08 11 09 9a 1f 10 28 ?? 00 00 0a d2 9c 11 09 17 58 13 09 11 09 08 8e 69 fe 04 13 0a 11 0a 2d dd}  //weight: 3, accuracy: Low
        $x_2_2 = "WindowsFormsApplication1.ChoiceProfile.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_DAO_2147841635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.DAO!MTB"
        threat_id = "2147841635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 13 05 2b 16 08 11 05 07 11 05 9a 1f 10 28 ?? 00 00 0a d2 9c 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d dd}  //weight: 2, accuracy: Low
        $x_1_2 = "DoodleJump.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_SPAU_2147841696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.SPAU!MTB"
        threat_id = "2147841696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 06 07 11 06 9a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d db}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_SPAB_2147841793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.SPAB!MTB"
        threat_id = "2147841793"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 11 05 07 11 05 9a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d db}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_SPU_2147844449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.SPU!MTB"
        threat_id = "2147844449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {16 13 04 2b 71 00 06 19 11 04 5a 6f ?? ?? ?? 0a 13 05 11 05 1f 39 fe 02 13 07 11 07 2c 0d 11 05 1f 41 59 1f 0a 58 d1 13 05 2b 08 11 05 1f 30 59 d1 13 05 06 19 11 04 5a 17 58 6f ?? ?? ?? 0a 13 06 11 06 1f 39 fe 02 13 08 11 08 2c 0d 11 06 1f 41 59 1f 0a 58 d1 13 06 2b 08 11 06 1f 30 59 d1 13 06}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_EAQ_2147844574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.EAQ!MTB"
        threat_id = "2147844574"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 15 2d 22 26 28 ?? 01 00 0a 06 6f ?? 01 00 0a 28 ?? 00 00 0a 16 2c 11 26 02 07 28 ?? 01 00 06 1e 2d 09 26 de 0c 0a 2b dc 0b 2b ed 0c 2b f5 26 de c9}  //weight: 3, accuracy: Low
        $x_2_2 = "WindowsFormsApp34.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_SPUT_2147845022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.SPUT!MTB"
        threat_id = "2147845022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 06 11 0a 09 11 0a 91 11 05 61 11 04 11 07 91 61 28 ?? ?? ?? 0a 9c 11 07 1f 15 fe 01 13 0b 11 0b 2c 05 16 13 07 2b 06 11 07 17 58 13 07 00 11 0a 17 58 13 0a 11 0a 09 8e 69 17 59 fe 02 16 fe 01 13 0c 11 0c 2d b8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_FAS_2147845788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.FAS!MTB"
        threat_id = "2147845788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 16 13 07 2b 1f 00 09 08 11 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f 79 00 00 0a 00 00 11 07 18 58 13 07 11 07 08 6f ?? 00 00 0a fe 04 13 08 11 08 2d d1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_FAR_2147846120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.FAR!MTB"
        threat_id = "2147846120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 01 2a 00 72 ?? 00 00 70 28 ?? 00 00 06 13 00 38 00 00 00 00 28 ?? 00 00 0a 11 00 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 06 13 01 38 00 00 00 00 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_NSS_2147846352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.NSS!MTB"
        threat_id = "2147846352"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 82 01 00 06 72 ?? ?? ?? 70 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 13 00 20 ?? ?? ?? 00 28 ?? ?? ?? 06 39 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "RHalH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_FAX_2147846376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.FAX!MTB"
        threat_id = "2147846376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 16 0d 2b 29 00 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 06 08 17 8d ?? 00 00 01 25 16 11 06 9c 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 07 11 07 2d c8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_FAY_2147846779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.FAY!MTB"
        threat_id = "2147846779"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 16 1f 2d 9d 6f ?? 01 00 0a 0b 07 8e 69 17 da 17 d6 8d ?? 00 00 01 0c 07 8e 69 17 da 13 06 16 13 07 2b 15 08 11 07 07 11 07 9a 1f 10 28 ?? 01 00 0a 9c 11 07 17 d6 13 07 11 07 11 06 31 e5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_SXO_2147888222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.SXO!MTB"
        threat_id = "2147888222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 06 08 91 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_KA_2147890155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.KA!MTB"
        threat_id = "2147890155"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "downloadserver.duckdns.org" wide //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "withoutstartup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_KA_2147890155_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.KA!MTB"
        threat_id = "2147890155"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://84.54.50.31/D" wide //weight: 1
        $x_1_2 = "BNBUN76.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_MAC_2147899443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.MAC!MTB"
        threat_id = "2147899443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get__10_historical_mistakes_in_the_movie_300" ascii //weight: 1
        $x_1_2 = "set_UseShellExecute" ascii //weight: 1
        $x_1_3 = "AssemblyInfo" ascii //weight: 1
        $x_1_4 = "get_cmdload" ascii //weight: 1
        $x_1_5 = "cmdreport" ascii //weight: 1
        $x_1_6 = "Enablefundtransfer" ascii //weight: 1
        $x_1_7 = "ToolStripItemClickedEventHandler" ascii //weight: 1
        $x_1_8 = "KeyEventHandler" ascii //weight: 1
        $x_1_9 = "ServerComputer" ascii //weight: 1
        $x_1_10 = "txtbankcode" ascii //weight: 1
        $x_1_11 = "UPDATE SAVINGS AND CREDIT" wide //weight: 1
        $x_1_12 = "\\metadata.txt" wide //weight: 1
        $x_1_13 = "\\pdftk.exe" wide //weight: 1
        $x_1_14 = "\\..\\statements" wide //weight: 1
        $x_1_15 = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_AYAA_2147900816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.AYAA!MTB"
        threat_id = "2147900816"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 04 0e 05 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_ASH_2147914383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.ASH!MTB"
        threat_id = "2147914383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 1a 00 02 06 7e ?? 00 00 04 06 91 03 06 0e 05 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b 07 2d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_ASI_2147916716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.ASI!MTB"
        threat_id = "2147916716"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 0a 02 28 ?? 00 00 06 0b 14 0c 00 73 ?? 00 00 0a 25 06 6f ?? 00 00 0a 00 25 07 6f ?? 00 00 0a 00 0c 08 6f ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 13 ?? de 1b 09 2c 07 09 6f}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_SMAA_2147916915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.SMAA!MTB"
        threat_id = "2147916915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {05 0a 06 0b 16 0c 2b 19 00 02 08 7e ?? 00 00 04 08 91 05 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e ?? 00 00 04 8e 69 fe 04 0d 09 2d d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_AZ_2147920915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.AZ!MTB"
        threat_id = "2147920915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6e 08 8e 69 6a 5d d4 91 58}  //weight: 2, accuracy: High
        $x_1_2 = {95 58 20 ff 00 00 00 5f 13}  //weight: 1, accuracy: High
        $x_1_3 = {95 61 d2 9c}  //weight: 1, accuracy: High
        $x_1_4 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BA_2147921660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BA!MTB"
        threat_id = "2147921660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 08 06 07 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 10 00 de 18 11 05 2c 07 11 05 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BB_2147922421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BB!MTB"
        threat_id = "2147922421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 07 6f ?? 00 00 0a 0c 2b 2d 00 03 12 ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 15 03 6f ?? 00 00 0a 19 58 04 31 03 16 2b 01 17 13}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BC_2147922890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BC!MTB"
        threat_id = "2147922890"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 06 07 6f ?? 00 00 0a 0c 2b 2d 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 14 03 6f ?? 00 00 0a 19 58 04 fe 02 16 fe 01 13 04 11 04 2d}  //weight: 2, accuracy: Low
        $x_2_2 = {03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 1a 09 17 fe 01 13 08 11 08 2c 10 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 00 07 17 58 0b 00 07 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BD_2147923281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BD!MTB"
        threat_id = "2147923281"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 04 03 6f ?? 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 ?? 11 ?? 2c 2f 00 03 19 8d ?? 00 00 01 25 16 12 ?? 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 ?? 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 2b ?? 09 16 fe 02 13 ?? 11 ?? 2c 65 00 19 8d ?? 00 00 01 25 16 12 ?? 28 ?? 00 00 0a 9c 25 17 12 ?? 28 ?? 00 00 0a 9c 25 18 12 ?? 28 ?? 00 00 0a 9c 13 06 19 8d ?? 00 00 01 25 17 17 9e 25 18 18 9e 13 ?? 16 13 ?? 2b 17}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BE_2147923492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BE!MTB"
        threat_id = "2147923492"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 0c 2b 15 00 02 08 03 08 91 05 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BF_2147923962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BF!MTB"
        threat_id = "2147923962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {95 13 13 11 12 11 13 61 13 14 11 05 11 11 11 14 d2 9c 11 07 17 58 13 07 00 11 07 6e 11 05 8e 69 6a fe 04}  //weight: 4, accuracy: High
        $x_1_2 = {95 58 20 ff 00 00 00 5f 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BG_2147924385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BG!MTB"
        threat_id = "2147924385"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 2c 07 09 6f ?? 00 00 0a 00 dc 28 ?? 00 00 06 0b 28 ?? 00 00 06 07 16 07 8e 69 6f ?? 00 00 0a 0c 08 28 ?? 00 00 06 26 00 de 0b}  //weight: 3, accuracy: Low
        $x_2_2 = {0d 00 09 28 ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 7e ?? 00 00 04 11 04 6f ?? 00 00 0a 00 00 de 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BH_2147924815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BH!MTB"
        threat_id = "2147924815"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {17 13 0c 09 11 0a 07 11 0a 91 11 04 11 0b 95 61 d2 9c 00 11 0a 17 58 13 0a 11 0a 07 8e 69 fe 04}  //weight: 3, accuracy: High
        $x_1_2 = {95 58 20 ff 00 00 00 5f}  //weight: 1, accuracy: High
        $x_1_3 = "4I87HHCHBJ8IT714P48RR4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BI_2147930211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BI!MTB"
        threat_id = "2147930211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 0f 00 28 ?? 00 00 0a 1a 5d 0f 00 28 ?? 00 00 0a 9c 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 28 ?? 00 00 06 0b 07 28 ?? 00 00 06 0c 2b 00 08 2a}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 02 04 05 28 ?? 00 00 06 0b 0e 04 03 6f ?? 00 00 0a 28 ?? 00 00 06 0c 03 07 08 28 ?? 00 00 06 00 2a}  //weight: 2, accuracy: Low
        $x_3_3 = {20 00 01 00 00 5a 6a 0a 02 03 28}  //weight: 3, accuracy: High
        $x_2_4 = {07 17 58 0b 07 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 05 fe 04 2b 01 16 0c 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BO_2147935907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BO!MTB"
        threat_id = "2147935907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 05 58 1d 5d 16 fe 01 13 06 11 06 13 07 11 07 2c 0c 08 11 05 1f 20 5b 28 ?? ?? 00 06 00 02 07 11 05 03 04 28 ?? ?? 00 06 00 00 11 05 17 58 13 05 11 05 02 6f ?? 00 00 0a 2f 0b 03 6f ?? ?? 00 0a 04 fe 04 2b 01 16 13 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BS_2147940597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BS!MTB"
        threat_id = "2147940597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {59 11 03 59 20 ff 00 00 00 5f d2 13}  //weight: 3, accuracy: High
        $x_2_2 = {fe ff ff 11 02 66 d2 13}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_BT_2147940671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.BT!MTB"
        threat_id = "2147940671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {59 13 0a 11 0a 19 fe 04 16 fe 01 13 10 11 10 2c 48 00 11 06 16 2f 07 11 08 16 fe 04 2b 01 16}  //weight: 4, accuracy: High
        $x_1_2 = {9c 25 17 12 09 28 ?? 00 00 0a 9c 25 18 12 09 28 ?? 00 00 0a 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_CE_2147941549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.CE!MTB"
        threat_id = "2147941549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2c 02 16 0b 28 ?? 00 00 0a 17 fe 02 0c 19 8d ?? 00 00 1b 25 16 06}  //weight: 2, accuracy: Low
        $x_2_2 = {1b 5d 0b 07 1a 2e 0e 07 19 2e 0a 07 18 2e 06 07 17 fe 01 2b 01 17}  //weight: 2, accuracy: High
        $x_1_3 = "r4Nd0m_5A1t" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_ACF_2147942720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.ACF!MTB"
        threat_id = "2147942720"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 26 12 24 28 ?? 00 00 0a 13 27 11 25 11 26 58 11 27 58 13 28 11 28 1f 1f 61 13 28 04 03 6f ?? 00 00 0a 59 13 29 11 29 17}  //weight: 4, accuracy: Low
        $x_1_2 = {2b 24 03 11 25 6f ?? 00 00 0a 00 03 11 26 6f ?? 00 00 0a 00 2b 10 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_ALWA_2147943481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.ALWA!MTB"
        threat_id = "2147943481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 07 6f ?? 00 00 0a 25 08 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 0d 09 6f ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 13 05 03 20 ?? ?? 00 00 28 ?? 00 00 06 11 05 6f ?? 00 00 06 17 13 06 de 33}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_AOWA_2147943789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.AOWA!MTB"
        threat_id = "2147943789"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {70 0b 06 8e 69 8d ?? 00 00 01 0c 16 0d 38 ?? 00 00 00 08 09 06 09 91 07 09 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_ENSJ_2147943996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.ENSJ!MTB"
        threat_id = "2147943996"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {15 6e 61 15 6e 61 7d 87 00 00 04 06 73 69 00 00 0a 7d 86 00 00 04 06 7b 86 00 00 04 72 66 05 00 70 16 1f 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_AEXA_2147944320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.AEXA!MTB"
        threat_id = "2147944320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 07 6f ?? 00 00 0a 25 08 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 0d 09 6f ?? 00 00 0a 13 04 2b 1f 2b 21 16 2b 21 8e 69 2b 20 2b 25 2b 27 72 ?? ?? 00 70 2b 23 16 2c 24 26 26 26 17 2b 25 de 5d 11 04 2b dd 06 2b dc 06 2b dc 6f ?? 00 00 0a 2b d9 13 05 2b d7 03 2b d6 11 05 2b d9 28 ?? 00 00 06 2b d8 13 06 2b d7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_AWXA_2147944884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.AWXA!MTB"
        threat_id = "2147944884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 21 17 11 26 16 94 11 26 17 94 58 1f 0a 5d 58 13 22 11 26 16 94 13 48 11 26 17 94 13 49 02 11 48 11 49 6f ?? 00 00 0a 13 4a 12 4a 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 5a 11 5a 2c 08 72 ?? 08 00 70 0c 2b 3e 12 4a 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 5b 11 5b 2c 08 72 ?? 08 00 70 0c 2b 22 12 4a 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 5c 11 5c 2c 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_ACH_2147945419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.ACH!MTB"
        threat_id = "2147945419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0f 00 28 ?? 00 00 0a 0b 0f 00 28 ?? 00 00 0a 0c 04}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 06 0e 07 0e 08 28 ?? 00 00 06 0b 03 04 0e 06 28 ?? 00 00 06 0c 03 07 08 0e 06 0e 08}  //weight: 1, accuracy: Low
        $x_3_3 = {06 16 61 d2 0a 07 20 ff 00 00 00 5f d2 0b 08 16 60 d2 0c 04}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_AVYA_2147945592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.AVYA!MTB"
        threat_id = "2147945592"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 04 6f ?? 00 00 0a 0a 12 01 fe ?? ?? 00 00 02 12 01 12 00 28 ?? 00 00 0a 7d ?? 01 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 01 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 01 00 04 12 01 07 7b ?? 01 00 04 07 7b ?? 01 00 04 5a 07 7b ?? 01 00 04 07 7b ?? 01 00 04 5a 58 07 7b ?? 01 00 04 07 7b ?? 01 00 04 5a 58 6c}  //weight: 5, accuracy: Low
        $x_2_2 = {04 6c 11 05 5a 13 06 07 11 06 58 0b 2b 24 02 7b ?? 01 00 04 6c 11 05 5a 13 06 08 11 06 58 0c 2b 11 02 7b ?? 01 00 04 6c 11 05 5a 13 06 09 11 06 58 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_ZER_2147945725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.ZER!MTB"
        threat_id = "2147945725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 03 04 6f ?? 00 00 0a 0a 12 01 fe ?? 11 00 00 02 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 16 7d ?? 00 00 04 07}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_ZKR_2147945949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.ZKR!MTB"
        threat_id = "2147945949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 03 04 6f ?? 00 00 0a 0a 12 01 fe ?? 1d 00 00 02 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 0e 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_AIZA_2147946102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.AIZA!MTB"
        threat_id = "2147946102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {05 0e 04 0e 06 0e 08 17 1f 20 28 ?? ?? 00 06 0a 06 0e 05 0e 07 1f 40 23 66 66 66 66 66 66 e6 3f 28 ?? ?? 00 06 0b 16 0d 2b b8 02 03 04 06 07 17 28 ?? ?? 00 06 06 07 0e 06 0e 08 1f 0c 17 28 ?? ?? 00 06 18 0d 2b 9b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_EKBH_2147946274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.EKBH!MTB"
        threat_id = "2147946274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5a 11 26 17 94 58 13 18 11 26 16 94 11 26 17 94 58 1f 19 5d 16 fe 01 13 19 11 26 17 94 19 5d 2c 17 11 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeLogger_ANAB_2147947381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeLogger.ANAB!MTB"
        threat_id = "2147947381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 11 03 02 11 03 91 11 01 11 03 11 01 6f ?? 00 00 0a 5d 28 ?? 00 00 06 61 d2 9c 20}  //weight: 5, accuracy: Low
        $x_2_2 = {11 03 17 58 13 03 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

