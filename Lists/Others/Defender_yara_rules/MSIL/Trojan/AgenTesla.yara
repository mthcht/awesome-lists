rule Trojan_MSIL_Agentesla_PSB_2147764838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agentesla.PSB!MTB"
        threat_id = "2147764838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agentesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "venpick" wide //weight: 1
        $x_1_2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide //weight: 1
        $x_1_3 = "WinRar.Compression" wide //weight: 1
        $x_1_4 = "StartGame" wide //weight: 1
        $x_1_5 = "Special Byte[]" wide //weight: 1
        $x_1_6 = "Invoke" wide //weight: 1
        $x_1_7 = "NonFiction" wide //weight: 1
        $x_1_8 = "Enter book genre:" wide //weight: 1
        $x_1_9 = "Enter book Author:" wide //weight: 1
        $x_1_10 = "Enter book title:" wide //weight: 1
        $x_1_11 = "venpick.Properties.Resources" wide //weight: 1
        $x_1_12 = "VNYCZCWSJKAA32GMZFNLZIXZFPTCAYGWRMOR4CGJ" ascii //weight: 1
        $x_1_13 = "venpickL3KGSFMSDVSHWJMNLZGXZFIAIZIX2" ascii //weight: 1
        $x_1_14 = "YEXT5NSD4ASZFNIDVCSGTJBAODSGHBUFA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agentesla_RT_2147780470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agentesla.RT!MTB"
        threat_id = "2147780470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agentesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 11 04 6f ?? ?? ?? ?? 13 05 11 05 28 ?? ?? ?? ?? 13 06 08 06 11 06 b4 9c 11 04 17 d6 13 04 11 04 16 31}  //weight: 1, accuracy: Low
        $x_1_2 = "ToWin32" ascii //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agentesla_AD_2147814565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agentesla.AD!MTB"
        threat_id = "2147814565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agentesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 11 05 28 ?? ?? 00 06 7e 0f 00 00 04 6f ?? ?? 00 0a 7e ?? ?? 00 0a 28 ?? ?? 00 06 17 6f ?? ?? 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {13 06 11 06 2c 61 1f 0c 8d ?? ?? 00 01 13 0f 11 0f 16 18 9c 11 0f 17 16 9c 11 0f 18 16 9c 11 0f 19 16 9c 11 0f 1a 16 9c}  //weight: 1, accuracy: Low
        $x_1_3 = {11 0f 1b 16 9c 11 0f 1c 16 9c 11 0f 1d 16 9c 11 0f 1e 16 9c 11 0f 1f 09 16 9c 11 0f 1f 0a 16 9c 11 0f 1f 0b 16 9c 11 0f 13 07 11 06}  //weight: 1, accuracy: High
        $x_1_4 = {11 0e 11 0d 9a 0d 09 6f ?? ?? 00 0a 6f ?? ?? 00 0a 28 ?? ?? 00 0a 0c 08 07 16 28 ?? ?? 00 0a 16 33 06 09 6f ?? ?? 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agentesla_ADA_2147818243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agentesla.ADA!MTB"
        threat_id = "2147818243"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agentesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 30 00 00 06 80 19 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 80 18 00 00 04 28 ?? ?? 00 06 28 ?? 00 00 0a 28 ?? ?? 00 06 28 ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {80 14 00 00 04 28 ?? 00 00 0a 28 ?? ?? 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {0b 07 28 22 02 00 06 6f ?? 00 00 0a 2c 11 07 28 22 02 00 06 28 fa 01 00 06 6f ?? 00 00 0a 0b de 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agentesla_PL_2147898598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agentesla.PL!MTB"
        threat_id = "2147898598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agentesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://picsum.photos/80" wide //weight: 1
        $x_1_2 = "RDEK YUMURTASI SAT" wide //weight: 1
        $x_1_3 = "{0}{1}Do you want to start another game?" wide //weight: 1
        $x_1_4 = "Its a tie!! {0}both of you got {1} pairs!" wide //weight: 1
        $x_1_5 = "inekYemVerbutton" wide //weight: 1
        $x_1_6 = "keciDurumlabel" wide //weight: 1
        $x_1_7 = "TAVUK YUMURTASI" wide //weight: 1
        $x_1_8 = "inekCanbar" wide //weight: 1
        $x_1_9 = "keciSatbutton" wide //weight: 1
        $x_1_10 = "inekSutlabel" wide //weight: 1
        $x_1_11 = "N DEPOSU" wide //weight: 1
        $x_1_12 = "tavukYemVerbutton" wide //weight: 1
        $x_1_13 = "inekSatbutton" wide //weight: 1
        $x_1_14 = "ordekSatbutton" wide //weight: 1
        $x_1_15 = "ordekDurumlabel" wide //weight: 1
        $x_1_16 = "tavukDurumlabel" wide //weight: 1
        $x_1_17 = "inek.wav" wide //weight: 1
        $x_1_18 = "keci.wav" wide //weight: 1
        $x_1_19 = "ordek.wav" wide //weight: 1
        $x_1_20 = "tavuk.wav" wide //weight: 1
        $x_1_21 = " you got no available move" wide //weight: 1
        $x_1_22 = "{0} you have no available move with [{1},{2}] dices" wide //weight: 1
        $x_1_23 = "{0} YOU ARE A WINNER !!!" wide //weight: 1
        $x_1_24 = "keciYemVerbutton" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

