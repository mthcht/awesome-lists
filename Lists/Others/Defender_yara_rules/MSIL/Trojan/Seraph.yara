rule Trojan_MSIL_Seraph_F_2147783880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.F!MTB"
        threat_id = "2147783880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 5f b8 13 04 11 06 09 84 95 13 05 11 06 09 84 11 06 11 04 84 95 9e 11 06 11 04 84 11 05 9e 11 07 11 08 02 11 08 91 11 06 11 06 09 84 95 11 06 11 04 84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 61 86 9c 11 08 17 d6 13 08}  //weight: 10, accuracy: High
        $x_10_2 = {20 00 01 00 00 5d 0c 07 09 94 13 04 07 09 07 08 94 9e 07 08 11 04 9e 07 07 09 94 07 08 94 58 20 00 01 00 00 5d 94 13 08 11 06 06 ?? 06 91 11 08 61 d2 9c 06 17 58 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Seraph_MS_2147784714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.MS!MTB"
        threat_id = "2147784714"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 8e 69 3f [0-4] 38 [0-4] 28 [0-4] 72 [0-4] 6f [0-4] 1d 3a [0-4] 26}  //weight: 1, accuracy: Low
        $x_1_2 = {11 01 11 01 11 ?? 94 11 ?? 11 ?? 94 58 20 ?? ?? ?? ?? 5d 94 13 ?? ?? ?? ?? ?? ?? 11 ?? 11 ?? 11 ?? 94 58 13 ?? 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 ?? 11 ?? 03 11 ?? 91 11 ?? 61 d2 9c 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_BU_2147788130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.BU!MTB"
        threat_id = "2147788130"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Message isn't WM_COPYDATA" wide //weight: 1
        $x_1_2 = "Catcher not started" wide //weight: 1
        $x_1_3 = "_00_Blanco" wide //weight: 1
        $x_1_4 = "_01_Smile" wide //weight: 1
        $x_1_5 = "_02_Laugh" wide //weight: 1
        $x_1_6 = "_03_Silly" wide //weight: 1
        $x_1_7 = "_04_Wink" wide //weight: 1
        $x_1_8 = "_05_Blush" wide //weight: 1
        $x_1_9 = "_06_Sad" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_A_2147793423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.A!MTB"
        threat_id = "2147793423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DOGGY.exe" ascii //weight: 1
        $x_1_2 = "Nbohqxzisjrgwzfnzdqeslby" ascii //weight: 1
        $x_1_3 = "connection" ascii //weight: 1
        $x_1_4 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "set_KeySize" ascii //weight: 1
        $x_1_7 = "get_KeySize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_B_2147793424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.B!MTB"
        threat_id = "2147793424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileInfo" ascii //weight: 1
        $x_1_2 = "/video/" ascii //weight: 1
        $x_1_3 = ").jpg" ascii //weight: 1
        $x_1_4 = "/video/ffmpeg.exe" ascii //weight: 1
        $x_1_5 = "Nwplwqujavdprwp" ascii //weight: 1
        $x_1_6 = "Semovmxzecptzr.Nwplwqujavdprwp.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_QQ_2147795465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.QQ!MTB"
        threat_id = "2147795465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 0a 2b 0e 20 e7 03 00 00 28 29 00 00 0a 06 17 58 0a 06 1f 14 32 ed}  //weight: 10, accuracy: High
        $x_3_2 = "ResourceHacker" ascii //weight: 3
        $x_3_3 = "eb tonnac margorp sihT!" ascii //weight: 3
        $x_3_4 = "niaMllDroC_" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_BI_2147796171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.BI!MTB"
        threat_id = "2147796171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xhoorxmov.Properties.Resources" wide //weight: 1
        $x_1_2 = "Nzsmadbwoufqqiofgvqvtpj" wide //weight: 1
        $x_1_3 = "TVqQAAMAAAAEAAAA" ascii //weight: 1
        $x_1_4 = "wershell" wide //weight: 1
        $x_1_5 = "FacadeExceptionCandidate" ascii //weight: 1
        $x_1_6 = "pm.Candidates" ascii //weight: 1
        $x_1_7 = "Test-NetConnection -TraceRoute youtube.com" wide //weight: 1
        $x_1_8 = "FromBase64String" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_G_2147799396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.G!MTB"
        threat_id = "2147799396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-4] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "Test-Connection www.google.com" ascii //weight: 1
        $x_1_3 = "Images.png" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "get_PixelFormat" ascii //weight: 1
        $x_1_6 = "powershell" ascii //weight: 1
        $x_1_7 = "Convert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_JNT_2147805549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.JNT!MTB"
        threat_id = "2147805549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 06 7b 05 00 00 04 09 9e 02 03 06 7b 05 00 00 04 17 59 28 06 00 00 06 02 06 7b 05 00 00 04 17 58 04 28 06 00 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_RG_2147837099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.RG!MTB"
        threat_id = "2147837099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FullInfoSender" ascii //weight: 1
        $x_1_2 = "AllWallets" ascii //weight: 1
        $x_1_3 = "RosComNadzor" ascii //weight: 1
        $x_1_4 = "adkasd8u3hbasd" ascii //weight: 1
        $x_1_5 = "kasdihbfpfduqw" ascii //weight: 1
        $x_1_6 = "sdfk83hkasd" ascii //weight: 1
        $x_1_7 = "asdaid9h24kasd" ascii //weight: 1
        $x_1_8 = "dvsjiohq3" ascii //weight: 1
        $x_1_9 = "blvnzcwqe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPQX_2147839453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPQX!MTB"
        threat_id = "2147839453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {06 06 4a 17 58 54 06 4a 07 8e 69 32 da 06 1a 58 16 52 de 30 73 3a 00 00 0a 2b bc}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_RDA_2147839573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.RDA!MTB"
        threat_id = "2147839573"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f3d9279a-903c-4094-bf42-a8bf28420c9d" ascii //weight: 1
        $x_1_2 = "646327bf-28d4-4749-8184-ca368e53c3fd" ascii //weight: 1
        $x_1_3 = "Desire.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_NFS_2147840173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.NFS!MTB"
        threat_id = "2147840173"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0e 00 00 0a 20 ?? ?? ?? 00 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 15 2d 20 26 26 6f ?? ?? ?? 0a 1c 2d 1d 26 07 28 ?? ?? ?? 0a 0c 08 16 08 8e 69 28 ?? ?? ?? 0a 08 0d}  //weight: 5, accuracy: Low
        $x_5_2 = {06 02 6f 0c 00 00 0a 18 2d 03 26 de 0a 0b 2b fb}  //weight: 5, accuracy: High
        $x_1_3 = "idyvt" ascii //weight: 1
        $x_1_4 = "bgwft" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPAK_2147840304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPAK!MTB"
        threat_id = "2147840304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 17 58 0a 06 08 8e 69 32 e3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPAG_2147840774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPAG!MTB"
        threat_id = "2147840774"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {91 06 04 1f 16 5d 91 61 28 ?? ?? ?? 0a 03 04 17 58 03 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 0b 2b 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPP_2147841494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPP!MTB"
        threat_id = "2147841494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 04 06 1a 58 4a 9a 09 28 ?? ?? ?? 0a 2c 13 16 3a 45 ff ff ff 11 04 06 1a 58 4a 17 58 9a 13 05 2b 16}  //weight: 4, accuracy: Low
        $x_1_2 = "Deeulbwjcv.Wdwkxeyaqaulcjiydowzeq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_DAB_2147841515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.DAB!MTB"
        threat_id = "2147841515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 1e 58 16 54 2b 24 08 06 1e 58 4a 18 5b 07 06 1e 58 4a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 06 1e 58 06 1e 58 4a 18 58 54 06 1e 58 4a 06 1a 58 4a 32 d2}  //weight: 4, accuracy: Low
        $x_1_2 = "ToByte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_DAC_2147842016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.DAC!MTB"
        threat_id = "2147842016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {26 07 18 5b 8d 02 00 00 01 1a 2d 0b 26 16 0d 2b 21 0a 2b e3 0b 2b ea 0c 2b f3 08 09 18 5b 06 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 09 18 58 0d 09 07 32 e4}  //weight: 3, accuracy: Low
        $x_3_2 = {26 07 18 5b 8d 02 00 00 01 1e 2d 0b 26 16 0d 2b 21 0a 2b e3 0b 2b ea 0c 2b f3 08 09 18 5b 06 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 09 18 58 0d 09 07 32 e4}  //weight: 3, accuracy: Low
        $x_1_3 = "ToByte" ascii //weight: 1
        $x_1_4 = "Substring" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Seraph_SPSP_2147842178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPSP!MTB"
        threat_id = "2147842178"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 9c 18 2c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_NES_2147842249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.NES!MTB"
        threat_id = "2147842249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 48 00 00 06 20 ?? ?? ?? 00 28 ?? ?? ?? 06 7e ?? ?? ?? 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 0b 07 74 ?? ?? ?? 1b 0a 38 ?? ?? ?? 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "Calculatrice VB.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPQ_2147842360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPQ!MTB"
        threat_id = "2147842360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_DAV_2147842557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.DAV!MTB"
        threat_id = "2147842557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 08 11 04 6f ?? 00 00 0a 13 05 06 11 05 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 28 ?? 00 00 06 0d 06 6f ?? 00 00 0a 09 16 09 8e 69 6f ?? 00 00 0a 13 06 de 2e}  //weight: 3, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_DAW_2147843837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.DAW!MTB"
        threat_id = "2147843837"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {15 2d 21 26 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 06 74 ?? 00 00 1b 28 ?? 00 00 06 15 2d 06 26 de 09 0a 2b dd 0b 2b f8 26 de cd}  //weight: 3, accuracy: Low
        $x_2_2 = "WindowsFormsApp56.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_PSKC_2147843940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.PSKC!MTB"
        threat_id = "2147843940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 0f 00 00 06 0a 28 0e 00 00 0a 06 6f 0f 00 00 0a 28 07 00 00 06 74 02 00 00 1b 28 06 00 00 06 0b dd 03 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_DAX_2147844726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.DAX!MTB"
        threat_id = "2147844726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 02 2a 00 28 ?? 00 00 06 13 00 38 00 00 00 00 28 ?? 00 00 0a 11 00 28 ?? 00 00 06 28 ?? 00 00 0a 13 01 38 00 00 00 00 02 11 01 28 ?? 00 00 06 13 02 38 00 00 00 00 dd}  //weight: 3, accuracy: Low
        $x_2_2 = "Bhbvtawafmh" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPAZ_2147845024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPAZ!MTB"
        threat_id = "2147845024"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b 1b 16 2c 1f 26 7e ?? ?? ?? 04 2b 1a 16 2b 1a 8e 69 2b 19 17 2c 04 2b 1b 2b 1c de 20 28 ?? ?? ?? 06 2b de 0a 2b df 06 2b e3 06 2b e3 28 ?? ?? ?? 06 2b e0 06 2b e2 0b 2b e1 26 de c2}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_PSKQ_2147845492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.PSKQ!MTB"
        threat_id = "2147845492"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 63 00 00 70 28 08 00 00 06 0b 28 1a 00 00 0a 07 6f 1b 00 00 0a 72 ab 00 00 70 7e 1c 00 00 0a 6f 1d 00 00 0a 28 1e 00 00 0a 0c de 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_NLM_2147845769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.NLM!MTB"
        threat_id = "2147845769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 7b 0a 00 00 04 6f ?? ?? ?? 0a 2d 55 28 ?? ?? ?? 0a 07 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 06 1a 58 16 54 2b 2c}  //weight: 5, accuracy: Low
        $x_1_2 = "Jepesbryqph" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_FAG_2147845934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.FAG!MTB"
        threat_id = "2147845934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 01 18 5b 8d ?? 00 00 01 13 02 38 ?? ff ff ff 11 00 28 ?? 00 00 06 13 01 38 ?? ff ff ff 11 02 11 03 18 5b 11 00 11 03 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 06 9c 20 03 00 00 00 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_FAI_2147845935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.FAI!MTB"
        threat_id = "2147845935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 02 2a 11 04 18 5b 8d ?? 00 00 01 13 02 20 04 00 00 00 38 ?? ff ff ff 11 03 18 58 13 03 38 ?? ff ff ff 11 02 11 03 18 5b 11 00 11 03 18 28 ?? 00 00 06 1f 10 28 ?? 00 00 0a 9c 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_FAU_2147845949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.FAU!MTB"
        threat_id = "2147845949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {17 2d 22 26 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 1b 2d 11 26 02 07 28 ?? 00 00 06 18 2d 09 26 de 0c 0a 2b dc 0b 2b ed 0c 2b f5 26 de c9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPD_2147846050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPD!MTB"
        threat_id = "2147846050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 16 11 06 11 06 25 17 58 13 06 28 ?? ?? ?? 0a 11 06 06 1a 58 4a 31 e8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_PSKY_2147846127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.PSKY!MTB"
        threat_id = "2147846127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 4f 00 00 70 28 27 00 00 06 13 01 20 00 00 00 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 39 0f 00 00 00 26 20 ?? ?? ?? 00 38 04 00 00 00 fe 0c 02 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 00 00 00 00 28 ?? ?? ?? 06 11 01 6f ?? ?? ?? 0a 72 8d 00 00 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 13 03 38 00 00 00 00 dd 93 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AS_2147846436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AS!MTB"
        threat_id = "2147846436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "del C:\\Windows\\Temp\\ /f /s /q" wide //weight: 2
        $x_2_2 = "del C:\\Windows\\Prefetch\\ /f /s /q" wide //weight: 2
        $x_2_3 = "del C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\ /f /s /q" wide //weight: 2
        $x_2_4 = "del C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History\\ /f /s /q" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AS_2147846436_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AS!MTB"
        threat_id = "2147846436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 28 ?? ?? ?? 06 13 00 38 00 00 00 00 28 ?? ?? ?? 0a 11 00 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 13 01}  //weight: 1, accuracy: Low
        $x_1_2 = {02 8e 69 17 59 13 03 38 0e 00 00 00 11 00 11 03 3c 4b 00 00 00 38 17 00 00 00 38 ed ff ff ff 38 49 00 00 00 02 11 00 02 11 03 91 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_FAT_2147846455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.FAT!MTB"
        threat_id = "2147846455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 26 16 25 2d 0a 2d 07 1e 2c 0a de 3b 2b 14 19 25 2c f0 2c e3 2b eb 2b 11 2b df 2b 14 2b dd 2b 17 2b db 2b 1a 16 2d e0 2b e5 28 ?? 00 00 06 2b e8 28 ?? 00 00 2b 2b e5 28 ?? 00 00 2b 2b e2 0a 2b e3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_PSNG_2147846480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.PSNG!MTB"
        threat_id = "2147846480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 28 7e 0b 00 00 04 20 74 be 66 06 2b 1f 2b 24 2b 29 1d 2c eb 16 2d 10 2b 24 2b 29 2b 2a 2b 2f 2b 34 28 01 00 00 2b 0b de 39 02 2b d5 28 08 00 00 06 2b da 28 38 00 00 06 2b d5 0a 2b d4 28 60 00 00 0a 2b d5 06 2b d4 6f 61 00 00 0a 2b cf 28 62 00 00 0a 2b ca 28 02 00 00 2b 2b c5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GIF_2147846541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GIF!MTB"
        threat_id = "2147846541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "208.67.107.146" ascii //weight: 1
        $x_1_2 = "Mvkgyzhe" ascii //weight: 1
        $x_1_3 = "Ugupnp" ascii //weight: 1
        $x_1_4 = "Sielxg" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "Axdmsayx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_NS_2147846587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.NS!MTB"
        threat_id = "2147846587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0c 00 00 06 2b cd 28 ?? 00 00 0a 2b cc 07 2b cb 6f ?? 00 00 0a 2b c6 6f ?? 00 00 0a 2b cb 28 ?? 00 00 0a 2b c6}  //weight: 5, accuracy: Low
        $x_1_2 = "Dezxgbj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_NS_2147846587_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.NS!MTB"
        threat_id = "2147846587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 63 57 8d c1 20 ?? ?? ?? 00 63 20 ?? ?? ?? 00 63 20 ?? ?? ?? ef 61 7d ?? ?? ?? 04 20 ?? ?? ?? 00 38 ?? ?? ?? ff 7e ?? ?? ?? 04 20 ?? ?? ?? b5 20 ?? ?? ?? 40 61 20 ?? ?? ?? 54 61 20 ?? ?? ?? a1 61 7d ?? ?? ?? 04}  //weight: 5, accuracy: Low
        $x_1_2 = "Jxunhca.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_NS_2147846587_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.NS!MTB"
        threat_id = "2147846587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7b 04 00 00 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 39 ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 73 ?? ?? ?? 0a 13 02 20 ?? ?? ?? 00 38 ?? ?? ?? ff 11 00 11 00 6f ?? ?? ?? 0a 11 00 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_2 = "Cuuoksbdd.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_NS_2147846587_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.NS!MTB"
        threat_id = "2147846587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0a 11 0a 6f 18 00 00 0a 11 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 0d 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 00 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 39 ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 11 0a 20 ?? ?? ?? 8c 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 20 ?? ?? ?? 00 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "Vpwbhlureu.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GAS_2147848007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GAS!MTB"
        threat_id = "2147848007"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {14 16 2c 43 26 2b 3b 1d 2c 38 00 1a 2c 2c 7e ?? 00 00 04 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 19 2d 03 26 de 06 0a 2b fb 26 de 00 06 2c c2}  //weight: 4, accuracy: Low
        $x_1_2 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GAP_2147848012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GAP!MTB"
        threat_id = "2147848012"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 2d df 2b f3 2b dd 00 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 16 2c 08 26 2b 00 16 2d d4 de c2 0a 2b f6 26 2b 00 de ba}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_PSPD_2147848072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.PSPD!MTB"
        threat_id = "2147848072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 30 00 00 06 28 32 00 00 06 74 42 00 00 01 28 31 00 00 06 74 04 00 00 1b 28 2e 00 00 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_NSE_2147848979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.NSE!MTB"
        threat_id = "2147848979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8f 10 00 00 01 25 47 07 08 07 8e 69 5d 91 61 d2 52 08 17 58 0c 08 06 8e 69}  //weight: 5, accuracy: High
        $x_1_2 = "EvadingSpoofer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_NSE_2147848979_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.NSE!MTB"
        threat_id = "2147848979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 18 00 00 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GKH_2147849815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GKH!MTB"
        threat_id = "2147849815"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 07 08 16 1a 6f ?? ?? ?? 0a 26 08 16 28 ?? ?? ?? 0a 0d 07 16 73 0b 00 00 0a 13 04 09 8d 07 00 00 01 13 05 11 04 11 05 16 09 6f ?? ?? ?? 0a 26 11 05 13 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AACV_2147849945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AACV!MTB"
        threat_id = "2147849945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 1a 8d ?? 00 00 01 0c 07 08 16 1a 6f ?? 00 00 0a 26 08 16 28 ?? 00 00 0a 0d 07 16 73 ?? 00 00 0a 13 04 09 8d ?? 00 00 01 13 05 11 04 11 05 16 09 6f ?? 00 00 0a 26 11 05 13 06 dd ?? 00 00 00 11 04 39 ?? 00 00 00 11 04 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GAQ_2147850111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GAQ!MTB"
        threat_id = "2147850111"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 13 04 16 13 05 11 04 12 05 28 ?? 00 00 0a 08 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a dd ?? 00 00 00 11 05 39 ?? 00 00 00 11 04 28 ?? 00 00 0a dc 09 18 58 0d 09 07 6f ?? 00 00 0a 32 bb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAGA_2147851075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAGA!MTB"
        threat_id = "2147851075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 7e ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 7e ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 14 0c}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAGI_2147851204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAGI!MTB"
        threat_id = "2147851204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 5b 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 14 0c 38}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAGL_2147851290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAGL!MTB"
        threat_id = "2147851290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 85 94 e8 85 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 da 94 e8 85 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 14 0b}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SXC_2147851313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SXC!MTB"
        threat_id = "2147851313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 20 00 01 00 00 6f ?? ?? ?? 0a 06 7e 01 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 7e 02 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 14 0c 38 44 00 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAGX_2147851521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAGX!MTB"
        threat_id = "2147851521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 b1 68 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 0c 68 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 28 ?? 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 de 1e 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAHE_2147851611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAHE!MTB"
        threat_id = "2147851611"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 5b 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 28 ?? 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 dd ?? 00 00 00 09 39 ?? 00 00 00 09 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SDX_2147851821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SDX!MTB"
        threat_id = "2147851821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 20 00 01 00 00 6f ?? ?? ?? 0a 06 72 01 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 72 5b 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 0a 00 00 0a 0c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAHX_2147851861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAHX!MTB"
        threat_id = "2147851861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 8a 66 01 1b 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 b9 66 01 1b 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0c 08 11 04 17 73 ?? 00 00 0a 0d 14 0b 2b 06 28 ?? 00 00 06 0b 07 2c f7 09 07 16 07 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 de 18}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAHY_2147851868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAHY!MTB"
        threat_id = "2147851868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 24 54 a3 d2 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 f9 55 a3 d2 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAHZ_2147851967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAHZ!MTB"
        threat_id = "2147851967"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 21 99 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 88 99 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAIL_2147852115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAIL!MTB"
        threat_id = "2147852115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 25 74 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 fc 74 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SDR_2147852122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SDR!MTB"
        threat_id = "2147852122"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 16 2b 1e 11 16 6f ?? ?? ?? 0a 13 3c 11 11 11 3c 11 1f 59 61 13 11 11 1f 19 11 11 58 1e 63 59 13 1f 11 16 6f ?? ?? ?? 06 2d d9 de 0c 11 16 2c 07}  //weight: 3, accuracy: Low
        $x_1_2 = "get_MetadataToken" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAIM_2147852194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAIM!MTB"
        threat_id = "2147852194"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 01 89 73 44 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 32 89 73 44 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAIY_2147852444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAIY!MTB"
        threat_id = "2147852444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 20 39 97 2e d7 28 ?? 02 00 06 28 ?? 01 00 0a 6f ?? ?? 00 0a 06 20 74 97 2e d7 28 ?? 02 00 06 28 ?? 01 00 0a 6f ?? ?? 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 01 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0c 08 11 04 17 73 ?? 00 00 0a 0d 09 07 16 07 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 de 1e 09 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAJA_2147852455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAJA!MTB"
        threat_id = "2147852455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 20 9d 3f 25 70 28 ?? 02 00 06 28 ?? 01 00 0a 6f ?? ?? 00 0a 06 20 d0 3f 25 70 28 ?? 02 00 06 28 ?? 01 00 0a 6f ?? ?? 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 01 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0c 08 11 04 17 73 ?? 00 00 0a 0d 09 07 16 07 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 de 1e 09 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAJK_2147852643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAJK!MTB"
        threat_id = "2147852643"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0c 08 11 04 17 73 ?? 00 00 0a 0d 09 07 16 07 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 de 1e 09 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAJR_2147852769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAJR!MTB"
        threat_id = "2147852769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0f 11 0f 28 ?? 00 00 06 11 0f 28 ?? 00 00 06 28 ?? 00 00 06 13 0b 20 03 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? ff ff ff 26 20 03 00 00 00 38 ?? ff ff ff 11 0f 20 ab 1d 00 00 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 20 02 00 00 00 fe 0e 08 00 38 ?? ff ff ff 73 ?? 00 00 0a 13 03}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAJV_2147852840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAJV!MTB"
        threat_id = "2147852840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0b 07 11 04 17 73 ?? 00 00 0a 0c 02 28 ?? 00 00 06 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 07 6f ?? 00 00 0a 13 05 de 18 08 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAJY_2147852863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAJY!MTB"
        threat_id = "2147852863"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 11 06 11 00 94 11 06 11 02 94 58 20 00 01 00 00 5d 94 13 03 38 ?? ff ff ff 11 02 11 06 11 00 94 58 13 02 38 ?? 00 00 00 11 06 11 00 94 13 04 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ASCU_2147852925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ASCU!MTB"
        threat_id = "2147852925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0c 08 11 04 17 73 ?? 00 00 0a 0d 09 07 16 07 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 de 1e}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAKB_2147852951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAKB!MTB"
        threat_id = "2147852951"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 08 07 17 73 ?? 00 00 0a 0d 02 28 ?? 00 00 06 75 ?? 00 00 1b 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 dd ?? 00 00 00 09 39 ?? 00 00 00 09 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAKH_2147852986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAKH!MTB"
        threat_id = "2147852986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 28 ?? 00 00 06 75 ?? 00 00 1b 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAKS_2147853144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAKS!MTB"
        threat_id = "2147853144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 06 6f ?? 01 00 0a 06 6f ?? 01 00 0a 6f ?? 01 00 0a 13 04 73 ?? 00 00 0a 0c 08 11 04 17 73 ?? 01 00 0a 0d 09 07 16 07 8e 69 6f ?? 01 00 0a 08 6f ?? 01 00 0a 13 05 de 1e 09 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAKT_2147853145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAKT!MTB"
        threat_id = "2147853145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0b 07 11 04 17 73 ?? 00 00 0a 0c 28 ?? 00 00 06 75 ?? 00 00 1b 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 07 6f ?? 00 00 0a 13 05 de 18}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAKZ_2147887405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAKZ!MTB"
        threat_id = "2147887405"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 c4 66 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 3d 66 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AALF_2147888138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AALF!MTB"
        threat_id = "2147888138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 8e 69 8d ?? 00 00 01 0b 16 0c 38 ?? 00 00 00 07 08 06 08 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPWR_2147888630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPWR!MTB"
        threat_id = "2147888630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0b 73 0b 00 00 0a 0c 08 07 17 73 0c 00 00 0a 0d 28 ?? ?? ?? 06 16 9a 75 01 00 00 1b 13 04 09 11 04 16 11 04 8e 69}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AANB_2147889012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AANB!MTB"
        threat_id = "2147889012"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 06 08 91 7e ?? 01 00 04 7e ?? 00 00 04 20 7f be 66 06 28 ?? 02 00 06 28 ?? 03 00 06 59 d2 9c 08 17 58 16 2c 12 26 08 06 8e 69 32 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AANL_2147889107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AANL!MTB"
        threat_id = "2147889107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 11 02 7e ?? 00 00 04 28 ?? 01 00 06 25 17 7e ?? 00 00 04 28 ?? 01 00 06 25 18 7e ?? 00 00 04 28 ?? 01 00 06 25 11 00 7e ?? 00 00 04 28 ?? 01 00 06 7e ?? 00 00 04 28 ?? 01 00 06 11 04 16 11 04 8e 69 7e ?? 00 00 04 28 ?? 01 00 06 13 03}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AANO_2147889301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AANO!MTB"
        threat_id = "2147889301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 72 01 00 00 70 28 ?? 00 00 0a 72 33 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 14 0d}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AANR_2147889323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AANR!MTB"
        threat_id = "2147889323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 20 6e b2 87 7d 28 ?? 00 00 06 28 ?? 00 00 0a 20 0f b2 87 7d 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 08 14 0b 2b 3d}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AANS_2147889398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AANS!MTB"
        threat_id = "2147889398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 07 14 0b 2b 0c 00 28 ?? 00 00 06 0b de 03 26 de 00 07 2c f1 73 ?? 00 00 0a 0c 07 73 ?? 00 00 0a 13 04 11 04 11 07 16 73 ?? 00 00 0a 13 05 11 05 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0a de 1e 11 05 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMAA_2147889486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMAA!MTB"
        threat_id = "2147889486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 01 11 03 11 00 11 03 91 72 ?? 00 00 70 28 ?? 00 00 06 59 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMAA_2147889486_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMAA!MTB"
        threat_id = "2147889486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 72 01 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 28 ?? 00 00 06 0c 73 ?? 00 00 0a 0d 08 73 ?? 00 00 0a 13 04 11 04 07 16 73 ?? 00 00 0a 13 05 11 05 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 06 dd}  //weight: 1, accuracy: Low
        $x_1_2 = "HttpClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AANZ_2147889494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AANZ!MTB"
        threat_id = "2147889494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 72 01 00 00 70 28 ?? 00 00 0a 72 33 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 04 14 13 05}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_NSA_2147889500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.NSA!MTB"
        threat_id = "2147889500"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 48 01 00 0a 6f ?? ?? ?? 0a 20 ?? ?? ?? 00 fe ?? ?? 00 38 ?? ?? ?? ff 11 0a 11 0a 6f ?? ?? ?? 0a 11 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 13 06 20 ?? ?? ?? 00 38 ?? ?? ?? ff 00 11 02 11 06 17 73 ?? ?? ?? 0a 13 03 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04}  //weight: 5, accuracy: Low
        $x_1_2 = "Yzpyszrb.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "ppburatp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAOD_2147890070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAOD!MTB"
        threat_id = "2147890070"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 03 72 01 00 00 70 28 ?? 00 00 0a 72 33 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 10}  //weight: 3, accuracy: Low
        $x_1_2 = "XEH4KJ2SNOJcVHi1qomIkA==" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAOH_2147890073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAOH!MTB"
        threat_id = "2147890073"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 20 ff b3 db e9 28 ?? 04 00 06 28 ?? 00 00 0a 20 80 b3 db e9 28 ?? 04 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 08}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAOK_2147890076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAOK!MTB"
        threat_id = "2147890076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 72 01 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 20 02 00 00 00 38}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAOO_2147890080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAOO!MTB"
        threat_id = "2147890080"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0f 20 4d 39 8f 2e 28 ?? 04 00 06 28 ?? 00 00 0a 20 32 39 8f 2e 28 ?? 04 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 08}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ASDV_2147890405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ASDV!MTB"
        threat_id = "2147890405"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 05 73 ?? 01 00 0a 0b 07 11 04 11 05 6f ?? 01 00 0a 13 06 73 ?? 00 00 0a 0a 03 75 ?? 00 00 1b 73 ?? 01 00 0a 0c 08 11 06 16 73 ?? 01 00 0a 0d 09 06 6f ?? 01 00 0a 73 ?? 01 00 06 06 6f ?? 00 00 0a 28 ?? 01 00 06 de}  //weight: 1, accuracy: Low
        $x_1_2 = {11 10 1e 63 d1 13 10 11 1c 11 09 91 13 25 11 1c 11 09 11 23 11 25 61 19 11 19 58 61 11 35 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAPD_2147891204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAPD!MTB"
        threat_id = "2147891204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 73 ?? 02 00 0a 0b 02 28 ?? 05 00 06 75 ?? 00 00 1b 73 ?? 02 00 0a 0c 08 11 04 16 73 ?? 02 00 0a 0d 09 07 6f ?? 02 00 0a 07 13 05 de 15 09 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ASDW_2147891258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ASDW!MTB"
        threat_id = "2147891258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 02 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 08 13 05 de 20 11 04 2c 07 11 04 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ASDX_2147891286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ASDX!MTB"
        threat_id = "2147891286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 02 1f 10 11 04 16 02 8e 69 1f 10 da 28 ?? 00 00 0a 00 00 73 ?? 00 00 0a 13 05 11 05 07 6f ?? 00 00 0a 00 11 05 17 6f ?? 00 00 0a 00 11 05 09 6f ?? 00 00 0a 00 00 11 05 6f ?? 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 07 11 07 0a de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAPG_2147891329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAPG!MTB"
        threat_id = "2147891329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 13 72 01 00 00 70 28 ?? 00 00 0a 72 33 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 04}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAPI_2147891380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAPI!MTB"
        threat_id = "2147891380"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 72 01 00 00 70 28 ?? 00 00 06 72 33 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 01}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMAE_2147891394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMAE!MTB"
        threat_id = "2147891394"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 1c d2 13 31 11 1c 1e 63 d1 13 1c 11 17 11 09 91 13 2c 11 17 11 09 11 ?? 11 ?? 61 11 1d 19 58 61 11 31 61 d2 9c ?? ?? ?? 58 13 09 11 2c 13 1d 11 09 11 25 32 a4}  //weight: 5, accuracy: Low
        $x_5_2 = {11 2e 11 14 11 0e 11 14 91 9d 11 14 17 58 13 14 11 14 11 1b 32 ea}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAPO_2147891481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAPO!MTB"
        threat_id = "2147891481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 02 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 08 13 05 de 20 11 04 2c 07 11 04 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAPU_2147891579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAPU!MTB"
        threat_id = "2147891579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 02 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 08 13 05 dd ?? 00 00 00 11 04 39 ?? 00 00 00 11 04 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPAD_2147891645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPAD!MTB"
        threat_id = "2147891645"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 82 00 00 0a 0c 08 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 1f 10 8d 5c 00 00 01 0d 02 09 1f 10 28 ?? ?? ?? 0a 00 02 8e 69}  //weight: 2, accuracy: Low
        $x_2_2 = {11 05 07 6f ?? ?? ?? 0a 00 11 05 17 6f ?? ?? ?? 0a 00 11 05 09 6f ?? ?? ?? 0a 00 00 11 05 6f ?? ?? ?? 0a 13 06 11 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAPV_2147891677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAPV!MTB"
        threat_id = "2147891677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 20 14 63 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 20 18 6f 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 06 13 01}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAPZ_2147891680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAPZ!MTB"
        threat_id = "2147891680"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 14 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 7e ?? 00 00 04 08 6f ?? 00 00 0a 14 6f ?? 00 00 0a de 20 11 04 2c 07 11 04 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAQG_2147891819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAQG!MTB"
        threat_id = "2147891819"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 06 72 01 00 00 70 28 ?? 00 00 0a 72 33 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAQI_2147891929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAQI!MTB"
        threat_id = "2147891929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 02 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 08 13 05 de 20 11 04 2c 07 11 04}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAQK_2147891963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAQK!MTB"
        threat_id = "2147891963"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 73 0c 00 00 0a 0c 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 dd ?? 00 00 00 11 04 39 ?? 00 00 00 11 04 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAQX_2147892174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAQX!MTB"
        threat_id = "2147892174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0a 20 3c 72 00 00 28 ?? 00 00 06 28 ?? 00 00 06 20 56 72 00 00 28 ?? 00 00 06 28 ?? 00 00 06 6f ?? 00 00 0a 13 07}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AARE_2147892353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AARE!MTB"
        threat_id = "2147892353"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 73 08 00 00 0a 0c 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 de 20 11 04 2c 07 11 04 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AARO_2147892472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AARO!MTB"
        threat_id = "2147892472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 09 20 11 75 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 20 3a 75 00 00 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 13 0a}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAQC_2147892499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAQC!MTB"
        threat_id = "2147892499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 01 11 01 11 03 94 11 01 11 02 94 58 20 00 01 00 00 5d 94 13 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMAC_2147892659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMAC!MTB"
        threat_id = "2147892659"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 12 d2 13 2f 11 12 1e 63 d1 13 12 11 1f 11 09 91 13 24 11 1f 11 09 11 24 11 27 61 19 11 18 58 61 11 2f 61 d2 9c 17 11 09 58 13 09 11 24 13 18 11 09 11 26 32 a4}  //weight: 1, accuracy: High
        $x_1_2 = {11 2c 11 16 11 14 11 16 91 9d 11 16 17 58 13 16 11 16 11 19 32 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMAF_2147892660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMAF!MTB"
        threat_id = "2147892660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 07 16 73 ?? 00 00 0a 13 05 11 05 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 28 ?? 00 00 06 de 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0b 14 0c 2b 0c 00 28 ?? 00 00 06 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AARZ_2147892712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AARZ!MTB"
        threat_id = "2147892712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 06 11 06 28 ?? 00 00 06 11 06 6f ?? 00 00 0a 28 ?? 00 00 06 13 07}  //weight: 3, accuracy: Low
        $x_1_2 = "5yGy4QKyvQd7JwR8Fe9VdDFG8IhAv/B5XCCUPkUS8G4=" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ASAT_2147892758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ASAT!MTB"
        threat_id = "2147892758"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 0d 08 09 16 1a 6f ?? 00 00 0a 26 09 16 28 ?? 00 00 0a 13 04 08 16 73 ?? 00 00 0a 13 05 11 04 8d ?? 00 00 01 13 06 11 05 11 06 16 11 04 6f ?? 00 00 0a 26 11 06 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AASB_2147892771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AASB!MTB"
        threat_id = "2147892771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 06 6f ?? 02 00 0a 06 6f ?? 02 00 0a 6f ?? 02 00 0a 13 04 73 ?? 00 00 0a 0b 28 ?? 0e 00 06 75 ?? 00 00 1b 73 ?? 01 00 0a 0c 08 11 04 16 73 ?? 02 00 0a 0d 09 07 6f ?? 02 00 0a 07 6f ?? 00 00 0a 13 05 de 1f 09 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AASK_2147892970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AASK!MTB"
        threat_id = "2147892970"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0a 20 d6 af 10 e7 28 ?? 00 00 06 28 ?? 00 00 06 20 f1 af 10 e7 28 ?? 00 00 06 28 ?? 00 00 06 6f ?? 00 00 0a 13 04}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ASDY_2147893075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ASDY!MTB"
        threat_id = "2147893075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 14 0d 2b 0c 00 28 ?? 00 00 06 0d de 03 26 de 00 09 2c f1 73 ?? 00 00 0a 13 04 09 73 ?? 00 00 0a 13 05 11 05 08 16 73 ?? 00 00 0a 13 06 11 06 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 0a de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AASW_2147893157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AASW!MTB"
        threat_id = "2147893157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 06 08 91 7e ?? 00 00 04 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AASX_2147893158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AASX!MTB"
        threat_id = "2147893158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 08 28 ?? 04 00 06 25 17 28 ?? 04 00 06 25 18 28 ?? 04 00 06 25 06 28 ?? 04 00 06 28 ?? 04 00 06 07 16 07 8e 69 28 ?? 04 00 06 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPXH_2147893313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPXH!MTB"
        threat_id = "2147893313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 07 02 07 91 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 e4}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AATG_2147893424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AATG!MTB"
        threat_id = "2147893424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 73 26 00 00 0a 0c 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 1e 2c 06 2b 0f 2b 11 2b 12 16 2d f4 2b 14 2b 15 2b 1a de 42 11 04 2b ed 08 2b ec 6f 29 00 00 0a 2b e7 08 2b e9 6f ?? 00 00 0a 2b e4 13 05 2b e2}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AATH_2147893425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AATH!MTB"
        threat_id = "2147893425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 02 07 91 20 aa fb 13 b6 28 ?? 00 00 06 28 ?? 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AATJ_2147893483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AATJ!MTB"
        threat_id = "2147893483"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 04 38 ?? 00 00 00 08 11 04 16 6f ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 13 06 09 11 06 6f ?? 00 00 0a 11 04 17 58 13 04 11 04 08 6f ?? 00 00 0a 32 d4 09 6f ?? 00 00 0a 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AATN_2147893568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AATN!MTB"
        threat_id = "2147893568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0d 09 07 16 73 ?? 00 00 0a 13 04 2b 12 2b 14 2b 15 7e ?? 00 00 04 2b 15 2b 16 14 2b 1a de 45 11 04 2b ea 08 2b e9 6f ?? 00 00 0a 2b e4 08 2b e8 6f ?? 00 00 0a 2b e3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AATS_2147893825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AATS!MTB"
        threat_id = "2147893825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 06 08 91 7e ?? 00 00 04 7e ?? 00 00 04 20 f8 be 66 06 28 ?? 02 00 06 28 ?? 03 00 06 59 d2 9c 08 17 58 16 2c 15 26 08 06 8e 69 16 2d f4 32 cf}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AATU_2147893826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AATU!MTB"
        threat_id = "2147893826"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 13 05 08 11 05 6f ?? 00 00 0a 09 17 58 0d 09 07 6f ?? 00 00 0a 32 d8 08 6f ?? 00 00 0a 13 06 de 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AATV_2147893827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AATV!MTB"
        threat_id = "2147893827"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0b 2b 1b 06 07 02 07 91 20 b4 f0 97 4e 28 ?? 00 00 06 28 ?? 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AATW_2147893834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AATW!MTB"
        threat_id = "2147893834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0b 2b 1b 06 07 02 07 91 20 37 7f 26 0e 28 ?? 00 00 06 28 ?? 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AATZ_2147893904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AATZ!MTB"
        threat_id = "2147893904"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 13 06 20 08 00 00 00 38 ?? ff ff ff 11 03 11 01 6f ?? 00 00 0a 3f ?? 00 00 00 20 05 00 00 00 38 ?? ff ff ff 11 01 11 03 16 28 ?? 00 00 06 13 04 20 02 00 00 00 7e ?? 09 00 04 7b ?? 09 00 04 39 ?? ff ff ff 26 20 02 00 00 00 38 ?? ff ff ff 11 08 11 0a 6f ?? 00 00 0a 20 05 00 00 00 7e}  //weight: 4, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMAG_2147893946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMAG!MTB"
        threat_id = "2147893946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 12 d2 13 2f 11 12 1e 63 d1 13 12 11 1f 11 09 91 13 24 11 1f 11 09 11 24 11 27 61 11 18 19 58 61 11 2f 61 d2 9c 17 11 09 58 13 09 11 24 13 18 11 09 11 26 32 a4}  //weight: 5, accuracy: High
        $x_5_2 = {11 2c 11 16 11 14 11 16 91 9d 17 11 16 58 13 16 11 16 11 19 32 ea}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMBA_2147893948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMBA!MTB"
        threat_id = "2147893948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0a 11 07 11 05 11 07 28 ?? 00 00 06 20 ?? ?? 00 00 61 d1 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMBA_2147893948_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMBA!MTB"
        threat_id = "2147893948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 11 03 11 01 11 03 91 11 00 59 d2 9c 20 ?? 00 00 00 38 ?? ff ff ff 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMBA_2147893948_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMBA!MTB"
        threat_id = "2147893948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 16 d2 13 2b 11 16 1e 63 d1 13 16 11 1e 11 09 91 13 23 11 1e 11 09 11 25 11 23 61 19 11 1d 58 61 11 2b 61 d2 9c 11 09 17 58 13 09 11 23 13 1d 11 09 11 27 32 a4}  //weight: 1, accuracy: High
        $x_1_2 = {11 33 11 13 11 0f 11 13 91 9d 17 11 13 58 13 13 11 13 11 1f 32 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPAL_2147894265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPAL!MTB"
        threat_id = "2147894265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 06 02 28 ?? ?? ?? 06 14 14 14 6f ?? ?? ?? 0a 26 00 16 2d ea}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPDD_2147894377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPDD!MTB"
        threat_id = "2147894377"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b 15 2b 16 14 2b 1a de 45 11 04 2b ea 08 2b e9 6f ?? ?? ?? 0a 2b e4 08 2b e8 6f ?? ?? ?? 0a 2b e3 6f ?? ?? ?? 0a 2b df 11 04 2c 07}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAUO_2147894557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAUO!MTB"
        threat_id = "2147894557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 01 11 03 16 28 ?? 00 00 06 13 0b 20 02 00 00 00 38 ?? ff ff ff 12 0b 28 ?? 00 00 0a 13 05 20 02 00 00 00 7e ?? 09 00 04 7b ?? 0a 00 04 3a ?? ff ff ff 26 20 06 00 00 00 38 ?? ff ff ff 11 0a 28 ?? 00 00 06 13 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAUP_2147894621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAUP!MTB"
        threat_id = "2147894621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 11 02 28 ?? 01 00 06 25 17 6f ?? 00 00 0a 25 18 28 ?? 01 00 06 25 11 00 28 ?? 01 00 06 6f ?? 00 00 0a 11 01 16 11 01 8e 69 28 ?? 01 00 06 13 03}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ASDZ_2147894680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ASDZ!MTB"
        threat_id = "2147894680"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 02 2a 11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 11 04 11 03 91 61 d2 9c 38 ?? 00 00 00 11 03 11 04 8e 69 ?? da ff ff ff 38 ?? ff ff ff 11 04 8e 69}  //weight: 1, accuracy: Low
        $x_1_2 = {58 5a 67 73 65 63 58 65 69 62 72 6d 6f 58 67 6d 69 56 23 65 78 63 62 6d 6f 49 57 7a 69 68 73 65 69 07 62 6d 7e 4f 4f 79 68 6b 78 4d 40 62 62 6b 7c 5c 71 72 7f 67 5a 5e 69 63 68 77 91 5b 74 70 78 62 5e 6d 76 6f 69 72 63 56 4c}  //weight: 1, accuracy: High
        $x_1_3 = "Zgyikreicbmo" wide //weight: 1
        $x_1_4 = "Gecqvlzrgyrqfssiz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAUV_2147894957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAUV!MTB"
        threat_id = "2147894957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 07 11 01 03 11 01 91 11 03 61 d2 9c 38 ?? 00 00 00 11 02 11 09 11 01 94 58 11 05 11 01 94 58 20 00 01 00 00 5d 13 02 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAUW_2147894958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAUW!MTB"
        threat_id = "2147894958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hfeiowf" ascii //weight: 1
        $x_1_2 = "Lgirjog" ascii //weight: 1
        $x_1_3 = "Gijrg" ascii //weight: 1
        $x_1_4 = "Wegfijrg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPGW_2147894978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPGW!MTB"
        threat_id = "2147894978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 04 07 11 04 16 73 ?? ?? ?? 0a 0c 08 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 13 05 de 6c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAUX_2147894985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAUX!MTB"
        threat_id = "2147894985"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 11 06 11 00 94 11 06 11 02 94 58 20 00 01 00 00 5d 94 13 03 38 ?? ff ff ff 11 06 11 01 11 01 9e}  //weight: 2, accuracy: Low
        $x_2_2 = {11 07 11 01 03 11 01 91 11 03 61 d2 9c}  //weight: 2, accuracy: High
        $x_2_3 = "Gqqcdwcdbgolvktnfdn" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAVA_2147895062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAVA!MTB"
        threat_id = "2147895062"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 7b 19 00 00 0a 02 7b 1c 00 00 0a 03 02 7b 1c 00 00 0a 91 02 7b 1b 00 00 0a 61 d2 9c}  //weight: 2, accuracy: High
        $x_2_2 = {02 02 7b 17 00 00 0a 02 7b 16 00 00 0a 02 7b 1c 00 00 0a 94 58 02 7b 1d 00 00 0a 02 7b 1c 00 00 0a 94 58 20 00 01 00 00 5d}  //weight: 2, accuracy: High
        $x_2_3 = "Wglwwkblvi" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAUU_2147895075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAUU!MTB"
        threat_id = "2147895075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fwefji" ascii //weight: 1
        $x_1_2 = "Mheurfg" ascii //weight: 1
        $x_1_3 = "Piusrhg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAVO_2147895475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAVO!MTB"
        threat_id = "2147895475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 20 5b be 66 06 28 ?? 00 00 06 28 ?? 00 00 06 7e ?? 00 00 04 20 3a be 66 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 13 0a}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ASFO_2147895491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ASFO!MTB"
        threat_id = "2147895491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kegrvuscxcpj525f7u94e6899tyht9l4" ascii //weight: 1
        $x_1_2 = "u5ytwqs97ecyx7bsnhtk2l2hv84k23a7" ascii //weight: 1
        $x_1_3 = "7pact3kum5mz7xu585kytbwpm96m5xhj" ascii //weight: 1
        $x_1_4 = "k82lhtmj3wavxtddxlp4n2n23gfjtj4n" ascii //weight: 1
        $x_1_5 = "3f73sjphtn5lb676tz72ywg3h7gllv7n" ascii //weight: 1
        $x_1_6 = "68j2cn7k4kad4cejchzba5g23xm2h67r" ascii //weight: 1
        $x_1_7 = "8r2btu49eyv2m5k6fk236524yp7x2usr" ascii //weight: 1
        $x_1_8 = "25cnlnzenytwsfmhextq86ncmhehgceu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAVQ_2147895496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAVQ!MTB"
        threat_id = "2147895496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 00 11 02 02 11 02 91 72 ?? 00 00 70 28 ?? 00 00 06 59 d2 9c}  //weight: 4, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAVU_2147895555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAVU!MTB"
        threat_id = "2147895555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 08 11 05 6f ?? 00 00 0a 20 07 00 00 00 38 ?? ff ff ff 38 ?? ff ff ff 20 03 00 00 00 38 ?? ff ff ff 11 01 11 09 16 28 ?? 00 00 06 13 0b 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? fe ff ff 26}  //weight: 4, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAVX_2147895715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAVX!MTB"
        threat_id = "2147895715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {94 58 02 7b ?? 00 00 0a 02 7b ?? 00 00 0a 94 58 20 00 01 00 00 5d 7d ?? 00 00 0a 38 ?? 00 00 00 02 03 8e 69 8d ?? 00 00 01 7d ?? 00 00 0a 38 ?? ff ff ff 02 02 7b ?? 00 00 0a 02 7b ?? 00 00 0a 94 7d ?? 00 00 0a 20 01 00 00 00 7e ?? 00 00 04 39 ?? fd ff ff 26 20 00 00 00 00 38 ?? fd ff ff 02 7b ?? 00 00 0a 02 7b ?? 00 00 0a 03 02 7b ?? 00 00 0a 91 02 7b ?? 00 00 0a 61 d2 9c 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAVY_2147895730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAVY!MTB"
        threat_id = "2147895730"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {94 58 20 00 01 00 00 5d 7d ?? 00 00 0a 20 08 00 00 00 38 ?? fd ff ff 02 02 7b ?? 00 00 0a 17 58 7d ?? 00 00 0a 20 01 00 00 00 7e ?? 00 00 04 3a ?? fd ff ff 26 38 ?? fd ff ff 02 7b ?? 00 00 0a 02 7b ?? 00 00 0a 03 02 7b ?? 00 00 0a 91 02 7b ?? 00 00 0a 61 d2 9c 20 09 00 00 00 7e ?? 00 00 04 39 ?? fd ff ff 26 38 ?? fd ff ff 02 03 8e 69 8d ?? 00 00 01 17 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAWB_2147895826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAWB!MTB"
        threat_id = "2147895826"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 06 72 3f 00 00 70 28 ?? 00 00 06 72 71 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 01}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAWF_2147895934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAWF!MTB"
        threat_id = "2147895934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 14 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 06 17 2c ec 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 16 2c 16 26 26 7e ?? 00 00 04 08 6f ?? 00 00 0a 14 16 2c 0c 26 26 26 de 34 6f ?? 00 00 0a 2b e5 6f ?? 00 00 0a 2b f0 11 04 2c 07 11 04 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GFA_2147896113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GFA!MTB"
        threat_id = "2147896113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "3EowPf59qzmwXdJvbCJLOvQkuLbGY8dk" ascii //weight: 2
        $x_2_2 = "Vusgrnmykdzrdyxgpnwtezp" ascii //weight: 2
        $x_2_3 = "FromBase64String" ascii //weight: 2
        $x_2_4 = "Invoke" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ASP_2147896126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ASP!MTB"
        threat_id = "2147896126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 15 2d 03 26 2b 3f 0a 2b fb 00 28 16 00 00 06 17 2d 26 26 28 0b 00 00 0a 07 6f 0c 00 00 0a 72 4b 00 00 70 7e 0d 00 00 0a 6f 0e 00 00 0a 28 0f 00 00 0a 16 2c 06 26 de 13 0b 2b d8 0c 2b f8 26 de 00 06 17 58 0a 06 1b 32 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GPA_2147896252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GPA!MTB"
        threat_id = "2147896252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 01 11 05 1f 18 63 d2 6f ?? 00 00 0a 20 0b 00 00 00 38}  //weight: 2, accuracy: Low
        $x_2_2 = {11 00 11 00 1f 0c 64 61 13 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAWI_2147896258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAWI!MTB"
        threat_id = "2147896258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 20 f9 bf 66 06 28 ?? 00 00 06 28 ?? 00 00 06 7e ?? 00 00 04 20 d8 bf 66 06 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 06 13 08 16 25 2d 15 7e ?? 00 00 04 7b ?? 00 00 04 16 2d 2c 2d 06 26 16 2b 02 11 04}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMAB_2147896269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMAB!MTB"
        threat_id = "2147896269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 01 11 03 11 00 11 03 91 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 0a 59 d2 9c}  //weight: 1, accuracy: Low
        $x_1_2 = {41 70 70 44 6f 6d 61 69 6e 00 67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 00 47 65 74 44 61 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_KAB_2147896282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.KAB!MTB"
        threat_id = "2147896282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 02 11 01 11 02 11 01 93 20 ?? 00 00 00 61 02 61 d1 9d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_KAC_2147896401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.KAC!MTB"
        threat_id = "2147896401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 11 02 02 11 02 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_KAC_2147896401_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.KAC!MTB"
        threat_id = "2147896401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 05 16 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 13 07 11 04 11 07 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 09 6f ?? 00 00 0a 32 d3}  //weight: 5, accuracy: Low
        $x_5_2 = "http://104.194.128.170" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GP_2147896643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GP!MTB"
        threat_id = "2147896643"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 1e 11 09 11 23 11 27 61 11 1d 19 58 61 11 32 61 d2 9c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ABYE_2147896755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ABYE!MTB"
        threat_id = "2147896755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {14 16 2c 03 26 2b 2c 0a 2b fb 00 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 1a 2d 09 26 12 00 1e 2d 06 26 de 0d 0a 2b f5 28 ?? 00 00 06 2b f4 26 de 00 06 2c d4}  //weight: 4, accuracy: Low
        $x_1_2 = "WindowsFormsApp75.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMBC_2147896946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMBC!MTB"
        threat_id = "2147896946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 07 11 05 11 07 28 ?? ?? 00 06 20 ?? ?? 00 00 61 d1 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAXA_2147897022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAXA!MTB"
        threat_id = "2147897022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 02 11 03 11 01 11 03 91 11 04 59 d2 9c 20 01 00 00 00 7e ?? 02 00 04 7b ?? 02 00 04 3a ?? fe ff ff 26 20 02 00 00 00 38 ?? fe ff ff 72 2f 00 00 70 28 ?? 00 00 0a 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAXH_2147897301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAXH!MTB"
        threat_id = "2147897301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 8e 69 5d 18 58 1b 58 1d 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1b 58 1d 59 91 61 28 ?? 00 00 0a 03 08 20 89 10 00 00 58 20 88 10 00 00 59 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAXI_2147897407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAXI!MTB"
        threat_id = "2147897407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 03 20 ae 51 6c ce 28 ?? 01 00 06 28 ?? 00 00 0a 20 89 51 6c ce 28 ?? 01 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 0c}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMBG_2147897542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMBG!MTB"
        threat_id = "2147897542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 1e 11 09 11 24 11 21 61 19 11 18 58 61 11}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAXS_2147897619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAXS!MTB"
        threat_id = "2147897619"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {14 0a 00 28 0e 00 00 06 0a 06 16 06 8e 69 28 01 00 00 0a 06 0b dd 03 00 00 00 26 de e5}  //weight: 4, accuracy: High
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPQN_2147897629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPQN!MTB"
        threat_id = "2147897629"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 16 06 8e 69 28 ?? ?? ?? 0a 06 0b dd ?? ?? ?? 00 26 de e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAXX_2147897633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAXX!MTB"
        threat_id = "2147897633"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {14 0a 00 28 ?? 00 00 06 0a 06 16 06 8e 69 28 ?? 00 00 0a 06 0b de 03 26 de e8}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAYF_2147898087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAYF!MTB"
        threat_id = "2147898087"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0a 11 09 11 02 11 09 91 11 08 11 09 11 08 28 ?? ?? 00 06 5d 6f ?? ?? 00 0a 61 d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPQF_2147898283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPQF!MTB"
        threat_id = "2147898283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 2d 00 00 01 25 16 1f 2c 9d 28 ?? ?? ?? 0a 0d 7e ?? ?? ?? 0a 13 04 16 13 05 16 13 06 16 13 07 2b 1f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPDF_2147898284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPDF!MTB"
        threat_id = "2147898284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {06 08 91 0d 06 08 06 07 08 59 17 59 91 9c 06 07 08 59 17 59 09 9c 08 17 58 0c 08 07 18 5b 32 e0}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAYI_2147898290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAYI!MTB"
        threat_id = "2147898290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 16 2c 43 26 06 8e 69 1c 2c 19 16 2d 2f 8d ?? 00 00 01 16 2c 34 26 16 15 2d 32 26 15 2c e6 06 8e 69 17 59 16 2c 29 26 2b 14 07 08 06 09 91 9c 08 16 2d d4 17 58 16 2c 1a 26 09 17 59 0d 09 16 2f e8 07 13 04 de 15 0a 2b bb 0b 2b ca 0c 2b cc 0d 2b d5 0c 2b e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMBE_2147898292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMBE!MTB"
        threat_id = "2147898292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 0b 1f f2 13 09 2b 9f 11 06 11 07 11 05 11 07 6f ?? 00 00 0a 20 ?? 0e 00 00 61 d1 9d 1f 0f 13 09}  //weight: 1, accuracy: Low
        $x_1_2 = {06 09 16 07 6f ?? 00 00 0a 26 1e 13 08 2b bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAYT_2147898585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAYT!MTB"
        threat_id = "2147898585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 09 91 13 04 06 09 06 07 09 59 17 59 91 9c 06 07 09 59 17 59 11 04 9c 09 17 58 0d 09 08 32 e0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAYV_2147898600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAYV!MTB"
        threat_id = "2147898600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 1c 11 04 06 08 06 91 20 b4 74 14 a6 28 ?? 00 00 06 28 ?? 00 00 0a 59 d2 9c 06 17 58 0a 06 08 8e 69 32 de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAYZ_2147898683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAYZ!MTB"
        threat_id = "2147898683"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6f 06 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 14 13 04 2b 3c 73 ?? 00 00 0a 13 05 11 05 20 72 8f 00 00 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 de 0c 11 05 2c 07 11 05 6f ?? 00 00 0a dc 11 04 2c c0 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 06 de 1e}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAZB_2147898685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAZB!MTB"
        threat_id = "2147898685"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 00 11 01 11 07 59 17 59 11 06 9c}  //weight: 2, accuracy: High
        $x_2_2 = {11 00 11 07 11 00 11 01 11 07 59 17 59 91 9c}  //weight: 2, accuracy: High
        $x_1_3 = "GetByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAZE_2147898706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAZE!MTB"
        threat_id = "2147898706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 08 06 09 91 9c 08 17 25 2c f1 58 0c 09 17 25 2c ea 59 0d 09 16 2f e8 07 13 04 de 30}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SSPP_2147898792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SSPP!MTB"
        threat_id = "2147898792"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {06 09 91 13 04 06 09 06 07 09 59 17 59 91 9c 06 07 09 59 17 59 11 04 9c 09 17 58 0d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SG_2147898801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SG!MTB"
        threat_id = "2147898801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 47 20 ab 00 00 00 61 d2 52 06 17 58 0a 06 03 8e 69 32 e5}  //weight: 2, accuracy: High
        $x_2_2 = "//downloadfilekee.lol/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAZM_2147898894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAZM!MTB"
        threat_id = "2147898894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {50 08 02 50 06 08 59 17 59 91 9c 02 50 06 08 59 17 59 09 9c 16 2d 14 16 2d da 08 17 58 0c 16 2d d5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAZP_2147898896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAZP!MTB"
        threat_id = "2147898896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 01 11 06 59 17 59 11 03 9c}  //weight: 2, accuracy: High
        $x_2_2 = {11 05 11 06 11 05 11 01 11 06 59 17 59 91 9c}  //weight: 2, accuracy: High
        $x_1_3 = "GetByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAZR_2147898986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAZR!MTB"
        threat_id = "2147898986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 00 11 07 11 00 11 01 11 07 59 17 59 91 9c}  //weight: 2, accuracy: High
        $x_2_2 = {11 00 11 01 11 07 59 17 59 11 08 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAYB_2147899009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAYB!MTB"
        threat_id = "2147899009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 11 07 11 01 94 11 07 11 03 94 58 20 00 01 00 00 5d 94 13 04}  //weight: 2, accuracy: High
        $x_2_2 = {11 08 11 02 11 09 11 02 91 11 04 61 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAZS_2147899049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAZS!MTB"
        threat_id = "2147899049"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 50 11 02 02 50 11 00 11 02 59 17 59 91 9c}  //weight: 2, accuracy: High
        $x_2_2 = {02 50 11 00 11 02 59 17 59 11 03 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAZT_2147899063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAZT!MTB"
        threat_id = "2147899063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 50 08 91 0d 02 50 08 02 50 06 08 59 17 59 91 9c 02 50 06 08 59 17 59 09 9c 08 17 58 0c 08 07 32 de}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAZX_2147899203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAZX!MTB"
        threat_id = "2147899203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 50 11 00 11 02 59 17 59 11 04 9c}  //weight: 2, accuracy: High
        $x_2_2 = {02 50 11 02 02 50 11 00 11 02 59 17 59 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAZZ_2147899229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAZZ!MTB"
        threat_id = "2147899229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 50 11 04 02 50 11 00 11 04 59 17 59 91 9c}  //weight: 2, accuracy: High
        $x_2_2 = {02 50 11 00 11 04 59 17 59 11 03 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAAA_2147899250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAAA!MTB"
        threat_id = "2147899250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 08 02 8e 69 5d 1f 0f 59 1f 0f 58 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 1f 09 58 1f 0a 58 1f 13 59 91 61 28 ?? 00 00 0a 02 08 20 89 10 00 00 58 20 88 10 00 00 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAAC_2147899442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAAC!MTB"
        threat_id = "2147899442"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {14 0a 00 73 ?? 00 00 0a 0b 28 ?? 00 00 06 0a de 07 07 6f ?? 00 00 0a dc 06 28 ?? 00 00 2b 28 ?? 00 00 2b 0a de 03 26 de d9}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAAG_2147899650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAAG!MTB"
        threat_id = "2147899650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {14 0a 00 73 ?? 00 00 0a 0b 28 ?? 00 00 06 0a dd ?? 00 00 00 07 39 ?? 00 00 00 07 6f ?? 00 00 0a dc 06 28 ?? 00 00 2b 28 ?? 00 00 2b 0a dd ?? 00 00 00 26 de cd}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAAI_2147899654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAAI!MTB"
        threat_id = "2147899654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 03 11 06 11 01 11 03 59 17 59 91 9c}  //weight: 2, accuracy: High
        $x_2_2 = {11 06 11 01 11 03 59 17 59 11 05 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAAL_2147899731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAAL!MTB"
        threat_id = "2147899731"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1c 2c 04 2b 04 2b 09 de 14 28 ?? 00 00 06 2b f5 0a 2b f4 07 2c 06 07 6f ?? 00 00 0a dc 2b 15 2b 16 2b 1b 2b 20 1e 2c d4 de 24 73 ?? ?? 00 0a 2b cd 0b 2b cc 06 2b e8 28 ?? 00 00 2b 2b e3 28 ?? 00 00 2b 2b de 0a 2b dd}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAAN_2147899814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAAN!MTB"
        threat_id = "2147899814"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 02 11 06 11 01 11 02 59 17 59 91 9c}  //weight: 2, accuracy: High
        $x_2_2 = {11 06 11 01 11 02 59 17 59 11 03 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ADAA_2147900164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ADAA!MTB"
        threat_id = "2147900164"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 2b 2e 16 2b 2e 2b 33 2b 38 16 2d 09 2b 09 2b 0a 6f ?? 00 00 0a de 10 08 2b f4 07 2b f3 08 2c 06 08 6f ?? 00 00 0a dc 07 6f ?? 00 00 0a 0d de 2e 06 2b cf 73 ?? 00 00 0a 2b cb 73 ?? 00 00 0a 2b c6 0c 2b c5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SSSP_2147900209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SSSP!MTB"
        threat_id = "2147900209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b 1e 11 0d 6f ?? ?? ?? 0a 13 25 11 0c 11 25 11 15 59 61 13 0c 11 15 11 0c 19 58 1e 63 59 13 15 11 0d 6f ?? ?? ?? 06 2d d9 de 0c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AEAA_2147900217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AEAA!MTB"
        threat_id = "2147900217"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 07 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 61 28 ?? 00 00 0a ?? 08 20 89 10 00 00 58 20 88 10 00 00 59 ?? 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AAAV_2147900420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AAAV!MTB"
        threat_id = "2147900420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 1c 11 04 06 08 06 91 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? ?? 00 0a 59 d2 9c 06 17 58 0a 06 08 8e 69 32 de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AQAA_2147900608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AQAA!MTB"
        threat_id = "2147900608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 50 08 91 0d 02 50 08 02 50 06 08 59 17 59 91 9c 02 50 06 08 59 17 59 09 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ARAA_2147900609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ARAA!MTB"
        threat_id = "2147900609"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 8e 69 17 59 0d 38 ?? 00 00 00 07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee}  //weight: 4, accuracy: Low
        $x_1_2 = "GetByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AVAA_2147900793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AVAA!MTB"
        threat_id = "2147900793"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 17 58 0a 06 1b 32 f8 03 75 ?? 00 00 1b 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_PTGF_2147900866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.PTGF!MTB"
        threat_id = "2147900866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {38 ea fa ff ff 11 01 28 ?? 00 00 06 11 07 28 ?? 00 00 06 28 ?? 00 00 06 6f 32 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_BAAA_2147900886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.BAAA!MTB"
        threat_id = "2147900886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 06 08 91 7e ?? 00 00 04 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e9 07 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_BFAA_2147900975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.BFAA!MTB"
        threat_id = "2147900975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 75 01 00 00 1b 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 2a 11 01 17 58 13 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_BJAA_2147901004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.BJAA!MTB"
        threat_id = "2147901004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 08 06 07 08 59 17 59 91 9c 06 07 08 59 17 59 09 9c 08 17}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_BKAA_2147901045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.BKAA!MTB"
        threat_id = "2147901045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 0a 2b 0e 02 06 02 06 91 1f 7b 61 d2 9c 06 17 58 0a 06 02 8e 69 32 ec}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPDU_2147901196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPDU!MTB"
        threat_id = "2147901196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 2b d9 06 2b e0 0a 2b e4 06 2b e3 03 2b e5 28 ?? ?? ?? 2b 2b e5 28 ?? ?? ?? 2b 2b e0 28 1a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_BTAA_2147901262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.BTAA!MTB"
        threat_id = "2147901262"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 1c de 20 28 ?? 00 00 06 2b e5 0a 2b e4 06 2b e6 06 2b e6 28 ?? 00 00 0a 2b e3 06 2b e2 0b 2b e1 26 de c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPDV_2147901365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPDV!MTB"
        threat_id = "2147901365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 28 01 00 00 2b 28 02 00 00 2b 28 51 00 00 0a 02 7b 15 00 00 04 03 04 58 07 58 6f 8d 00 00 06 6f 52 00 00 0a 28 03 00 00 2b 25 2d 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_CCAA_2147901455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.CCAA!MTB"
        threat_id = "2147901455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 08 28 02 00 00 2b 28 ?? 00 00 2b 13 08 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPCX_2147901597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPCX!MTB"
        threat_id = "2147901597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 73 36 00 00 0a 28 ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 09 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 13 04 11 04 13 07 de 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_CMAA_2147901706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.CMAA!MTB"
        threat_id = "2147901706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 16 06 8e 69 28 ?? 00 00 0a 38 ?? 00 00 00 07 16 3c ?? 00 00 00 28 ?? 00 00 06 38 ?? 00 00 00 28 ?? 00 00 06 06 28 ?? 00 00 0a 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPPX_2147901908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPPX!MTB"
        threat_id = "2147901908"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 07 18 5d 2d 07 28 ?? ?? ?? 06 2b 05 28 ?? ?? ?? 06 06 16 06 8e 69 28 ?? ?? ?? 0a 2b 10 07 16 2f 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AMCC_2147901982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AMCC!MTB"
        threat_id = "2147901982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 06 28 ?? 00 00 0a 16 14 28 ?? 00 00 06 00 28 ?? 00 00 0a 6f ?? 00 00 0a 00 dd}  //weight: 1, accuracy: Low
        $x_1_2 = {06 1f 20 58 28 ?? 00 00 0a 52 06 1f 20 58 46 2c 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_CYAA_2147902018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.CYAA!MTB"
        threat_id = "2147902018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 0b 2b 0e 06 07 02 07 91 1f 7b 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ec}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_DHAA_2147902221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.DHAA!MTB"
        threat_id = "2147902221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0d 02 18 5d 2d 07 28 ?? 00 00 0a 2b 05 28 ?? 00 00 0a 09 28 ?? 00 00 0a 2b 12 02 16 2f 08 16 28 ?? 00 00 0a 2b 06 16 28 ?? 00 00 0a 09 28 ?? 00 00 0a 13 05}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_DIAA_2147902284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.DIAA!MTB"
        threat_id = "2147902284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 04 11 05 58 13 04 11 05 17 58 13 05 11 05 02 31 ee}  //weight: 4, accuracy: High
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPPY_2147902323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPPY!MTB"
        threat_id = "2147902323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {38 00 00 00 00 11 09 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 09 20}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ASBA_2147902396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ASBA!MTB"
        threat_id = "2147902396"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eyJuYW1lIjoiYXV0aDAuanMiLCJ2ZXJzaW9uIjoiOS4xMC40In0=" wide //weight: 1
        $x_1_2 = "JR1CoTOwE2qt6puwg8OwKHxDkVjBF6yT" wide //weight: 1
        $x_1_3 = "pornhub.com/signup" wide //weight: 1
        $x_1_4 = "Domain Sorter/@gmx.net.txt" wide //weight: 1
        $x_1_5 = "pornhub.com/user/create_account_check?token=MTYxNzQwMTY2N_puALWWs1jPGBfZLAVGzglGSVE" wide //weight: 1
        $x_1_6 = "Not Registered.txt" wide //weight: 1
        $x_1_7 = "====================SUBS==================" wide //weight: 1
        $x_1_8 = "Deliveroo VM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPYU_2147902839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPYU!MTB"
        threat_id = "2147902839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 15 31 0c 07 28 ?? ?? ?? 2b 28 02 00 00 2b 0b}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_EQAA_2147903179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.EQAA!MTB"
        threat_id = "2147903179"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 08 20 8a 10 00 00 58 20 89 10 00 00 59 03 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_EVAA_2147903183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.EVAA!MTB"
        threat_id = "2147903183"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 04 08 20 8a 10 00 00 58 20 89 10 00 00 59 04 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_FFAA_2147903193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.FFAA!MTB"
        threat_id = "2147903193"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 07 08 07 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 61 ?? 08 20 8a 10 00 00 58 20 89 10 00 00 59}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_FPAA_2147903415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.FPAA!MTB"
        threat_id = "2147903415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 08 20 8b 10 00 00 58 20 8a 10 00 00 59 03 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_FTAA_2147903562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.FTAA!MTB"
        threat_id = "2147903562"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 16 11 00 8e 69 28 ?? 00 00 0a 20 00 00 00 00 7e ?? 00 00 04 7b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPCZ_2147903567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPCZ!MTB"
        threat_id = "2147903567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 07 02 11 09 06 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 11 08 17 58 13 08 11 08 11 05 8e 69 32 ad}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GBAA_2147903766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GBAA!MTB"
        threat_id = "2147903766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {14 13 04 2b 14 00 28 ?? 00 00 06 13 04 11 04 28 ?? 00 00 0a de 03 26 de 00 11 04 2c e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPDC_2147903834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPDC!MTB"
        threat_id = "2147903834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 01 00 00 0a 72 01 00 00 70 28 ?? ?? ?? 0a 0a 06 16 06 8e 69 28 ?? ?? ?? 0a dd 09 00 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPBP_2147904143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPBP!MTB"
        threat_id = "2147904143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 06 07 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 16 07 8e 69 6f ?? ?? ?? 0a de 03 26}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_MBZB_2147904267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.MBZB!MTB"
        threat_id = "2147904267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 0b 28 0c 00 00 06 0b 06 07 28 01 00 00 2b 28 02 00 00 2b 16 07 8e 69}  //weight: 1, accuracy: High
        $x_1_2 = {49 53 68 61 70 65 00 43 69 72 63 6c 65 00 52 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GMAA_2147904283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GMAA!MTB"
        threat_id = "2147904283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 17 58 0a 06 20 00 01 00 00 5d 0a 08 11 06 06 94 58 0c 08 20 00 01 00 00 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 11 06 08 11 04 9e 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 11 07 07 03 07 91 09 61 d2 9c 07 17 58 0b 07 03 8e 69 3f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GRAA_2147904387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GRAA!MTB"
        threat_id = "2147904387"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 91 61 04 08 20 ?? ?? 00 00 58 20 ?? ?? 00 00 59 04 8e 69 5d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_GUAA_2147904470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.GUAA!MTB"
        threat_id = "2147904470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 03 28 ?? 00 00 2b 28 ?? 00 00 2b 16 11 03 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_HEAA_2147904829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.HEAA!MTB"
        threat_id = "2147904829"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 00 0a 0a 06 28 ?? ?? 00 0a 02 06 28 ?? 02 00 0a 7d ?? 00 00 04 de 03 26 de 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_HNAA_2147904954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.HNAA!MTB"
        threat_id = "2147904954"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 01 11 04 11 00 11 04 91 11 02 11 04 11 02 28 ?? 00 00 06 5d 28 ?? 00 00 06 61 d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPBN_2147905292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPBN!MTB"
        threat_id = "2147905292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 05 16 73 ?? ?? ?? 0a 13 04 11 04 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 0b de 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_HZAA_2147905332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.HZAA!MTB"
        threat_id = "2147905332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 2b 0c 00 28 ?? 00 00 06 0a de 03 26 de 00 06 2c f1 73 ?? 00 00 0a 0d 06 73 ?? 00 00 0a 13 04 11 04 08 16 73 ?? 00 00 0a 13 05 11 05 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 0a de 2c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_IAAA_2147905333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.IAAA!MTB"
        threat_id = "2147905333"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {91 07 06 1a 58 4a 07 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 61 03 06 1a 58 4a 20 ?? ?? 00 00 58 20 ?? ?? 00 00 59 03 8e 69 5d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_IRAA_2147905866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.IRAA!MTB"
        threat_id = "2147905866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0d 38 16 00 00 00 08 09 07 09 91 72 01 00 00 70 28 ?? 00 00 0a 59 d2 9c 09 17 58 0d 09 07 8e 69 32 e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_KAE_2147907696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.KAE!MTB"
        threat_id = "2147907696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 06 08 91 7e ?? ?? 00 04 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_KNAA_2147907704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.KNAA!MTB"
        threat_id = "2147907704"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0c 11 0c 28 ?? 00 00 06 11 0c 28 ?? 00 00 06 28 ?? 00 00 06 13 02}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPDH_2147907726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPDH!MTB"
        threat_id = "2147907726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 91 61 11 [0-10] 91 59 20 00 01 00 00 58 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPFV_2147908220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPFV!MTB"
        threat_id = "2147908220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 02 07 6f 7e 00 00 0a 03 07 6f 7e 00 00 0a 61 60 0a 07 17 58 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_MSAA_2147910276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.MSAA!MTB"
        threat_id = "2147910276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 2b 23 00 14 0b 28 ?? ?? 00 06 0b 06 07 28 ?? 00 00 2b 28 ?? 00 00 2b 16 07 8e 69 6f ?? ?? 00 0a de 03}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ZY_2147910583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ZY!MTB"
        threat_id = "2147910583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_crypted.exe" ascii //weight: 1
        $x_1_2 = "zEkkftLuEyTnmmsPhFoQgftXPNyr" ascii //weight: 1
        $x_1_3 = "xFNWWKTIVsvzbnsOnMoPUuAIb" ascii //weight: 1
        $x_1_4 = "wMuoRgWyDxOroctqwszzWfiOUSG" ascii //weight: 1
        $x_1_5 = "JhVIBhAQogcsuVUMBdqvfbwoH" ascii //weight: 1
        $x_1_6 = "VgbKyrhLBYZNmQWhJrZcrxbDAyk" ascii //weight: 1
        $x_1_7 = "Debugger" ascii //weight: 1
        $x_1_8 = "d58e08cd-3b9b-4e9b-b04a-2c9ef8faab75" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_ARA_2147910757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.ARA!MTB"
        threat_id = "2147910757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 16 11 04 8e 69 28 0d 00 00 0a}  //weight: 2, accuracy: High
        $x_2_2 = ".edom SOD ni nur eb tonnac margorp sihT!" ascii //weight: 2
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SSXP_2147910851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SSXP!MTB"
        threat_id = "2147910851"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {7e 02 00 00 04 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2c 06 08 6f ?? ?? ?? 0a de 03 26 de 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_OVAA_2147912494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.OVAA!MTB"
        threat_id = "2147912494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 16 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 16 13 04 38 1c 00 00 00 09 08 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 18 58 13 04 11 04 08 6f ?? 00 00 0a 32 da 06 09 6f ?? 00 00 0a 6f ?? 00 00 0a 06}  //weight: 4, accuracy: Low
        $x_1_2 = "GetByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_UBAA_2147919099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.UBAA!MTB"
        threat_id = "2147919099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 1d 58 1d 59 91 61 03 06 1a 58 4a 20 10 02 00 00 58 20 0f 02 00 00 59 03 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 1b 58 1b 59 91 59 20 fc 00 00 00 58 1a 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_UIAA_2147919389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.UIAA!MTB"
        threat_id = "2147919389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 20 ?? 77 00 00 28 ?? 01 00 06 28 ?? 00 00 0a 20 ?? 77 00 00 28 ?? 01 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 0a de 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_UZAA_2147919933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.UZAA!MTB"
        threat_id = "2147919933"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {91 61 04 08 20 0f 02 00 00 58 20 0e 02 00 00 59 18 59 18 58 04 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_SPXF_2147928388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.SPXF!MTB"
        threat_id = "2147928388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 02 09 91 06 08 93 28 ?? ?? ?? 0a 61 d2 9c 08 17 58 0c 09 17 58 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AYMA_2147935100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AYMA!MTB"
        threat_id = "2147935100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 11 00 91 13 02 38 ?? 00 00 00 03 8e 69 17 59 13 01 20 04 00 00 00 38 ?? ff ff ff 11 00 17 58 13 00 38 ?? 00 00 00 03 11 00 03 11 01 91 9c 38 ?? 00 00 00 11 01 17 59 13 01 20 01 00 00 00 7e}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Seraph_AWUA_2147942065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Seraph.AWUA!MTB"
        threat_id = "2147942065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 04 2b 1f 08 11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da 06 08 6f ?? 00 00 0a 06 16 6f ?? 00 00 0a 13 05 de 03 26 de 93 11 05 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

