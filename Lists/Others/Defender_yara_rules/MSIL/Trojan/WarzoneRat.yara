rule Trojan_MSIL_WarzoneRat_DA_2147773117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WarzoneRat.DA!MTB"
        threat_id = "2147773117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WarzoneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$b587aad2-1ea4-416f-9904-bd8d4af3a072" ascii //weight: 1
        $x_1_2 = "TankGame.My.Resources" ascii //weight: 1
        $x_1_3 = "TankGame.Resources" ascii //weight: 1
        $x_1_4 = "resources\\Images\\tut.png" ascii //weight: 1
        $x_1_5 = "resources\\Images\\tank.png" ascii //weight: 1
        $x_1_6 = "Nobody has won!" ascii //weight: 1
        $x_1_7 = "Javanese Text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WarzoneRat_DB_2147773118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WarzoneRat.DB!MTB"
        threat_id = "2147773118"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WarzoneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$a813f7ca-65b7-4e6a-bee3-4df825384be2" ascii //weight: 1
        $x_1_2 = "FileReplacement.My.Resources" ascii //weight: 1
        $x_1_3 = "FileReplacement.Resources" ascii //weight: 1
        $x_1_4 = "Neutral Evil" ascii //weight: 1
        $x_1_5 = "Chaotic Evil" ascii //weight: 1
        $x_1_6 = "Lawful Evil" ascii //weight: 1
        $x_1_7 = "Race: Gnome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WarzoneRat_DC_2147773469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WarzoneRat.DC!MTB"
        threat_id = "2147773469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WarzoneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$3B8E15D3-D40F-4E21-8A0E-ABA26283F02E" ascii //weight: 1
        $x_1_2 = "WindowsApplication1.BuryAlive.resources" ascii //weight: 1
        $x_1_3 = "Use letters dummy!" ascii //weight: 1
        $x_1_4 = "Alien Game" ascii //weight: 1
        $x_1_5 = "Hangman" ascii //weight: 1
        $x_1_6 = "lose.png" ascii //weight: 1
        $x_1_7 = "win.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WarzoneRat_DF_2147773522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WarzoneRat.DF!MTB"
        threat_id = "2147773522"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WarzoneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$c055c0df-0e9a-457f-a596-086774f390fb" ascii //weight: 1
        $x_1_2 = "HaploTree.My.Resources" ascii //weight: 1
        $x_1_3 = "HaploTree.Enterpise" ascii //weight: 1
        $x_1_4 = "set_ConnectionString" ascii //weight: 1
        $x_1_5 = "remove_MouseDoubleClick" ascii //weight: 1
        $x_1_6 = "get_CurrentDomain" ascii //weight: 1
        $x_1_7 = "MyTest.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WarzoneRat_DD_2147777285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WarzoneRat.DD!MTB"
        threat_id = "2147777285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WarzoneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$065432c9-77f1-4376-b0fc-b1caec24e2ba" ascii //weight: 1
        $x_1_2 = "Model.Properties.Resources" ascii //weight: 1
        $x_1_3 = "Model.Form1.resources" ascii //weight: 1
        $x_1_4 = "KurdishCoderProducts" ascii //weight: 1
        $x_1_5 = "CheckFrequencies" ascii //weight: 1
        $x_1_6 = "get_rainbowsix" ascii //weight: 1
        $x_1_7 = "get_sako" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WarzoneRat_AW_2147893833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WarzoneRat.AW!MTB"
        threat_id = "2147893833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WarzoneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {17 13 13 2b 1c 00 11 12 20 fc 00 00 00 16 16 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 13 17 58 13 13 11 13 1f 10 fe 04 13 14 11 14 2d d8}  //weight: 2, accuracy: Low
        $x_1_2 = "Convert bmp extracted from PoP 1 dat files into transparent png sprite sheets" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WarzoneRat_AWZ_2147894553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WarzoneRat.AWZ!MTB"
        threat_id = "2147894553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WarzoneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 0b 2b 23 00 08 17 5f 13 04 08 17 64 0c 11 04 16 fe 03 13 05 11 05 2c 08 08 20 01 a0 00 00 61 0c 00 07 17 58 d2 0b 07 1e fe 02 16 fe 01 13 06 11 06 2d d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WarzoneRat_DE_2147899382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WarzoneRat.DE!MTB"
        threat_id = "2147899382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WarzoneRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$8931c2cb-146f-42da-b666-fb71bfa04fec" ascii //weight: 1
        $x_1_2 = "Pharmacy.EnterpriseServicesHelper.resources" ascii //weight: 1
        $x_1_3 = "Pharmacy.My.Resources" ascii //weight: 1
        $x_1_4 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_5 = "Bharat Biotech" ascii //weight: 1
        $x_1_6 = "get_HotTrack" ascii //weight: 1
        $x_1_7 = "LoadHint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

