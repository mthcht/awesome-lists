rule Trojan_MSIL_Torwofun_A_2147693623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Torwofun.A"
        threat_id = "2147693623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Torwofun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "(SystemAutorun|node-webkit|UnLoad|" wide //weight: 4
        $x_4_2 = "TorProject|tor|AntiSpy|InstallMoney)" wide //weight: 4
        $x_4_3 = "|AntiSpy|InstallMoney|\\\\tor|\\\\Temp" wide //weight: 4
        $x_4_4 = "|156.154.71.1|193.58.251.251|198.153.19(2|4).1|" wide //weight: 4
        $x_4_5 = "QipGuard.exe|Clip2Net\\\\Clip2Net.exe|QIP 2012\\\\qip.exe|SynTP" wide //weight: 4
        $x_4_6 = "\\ShimInclusionList\\amigo.exe" wide //weight: 4
        $x_2_7 = "SystemAutorun.exe" wide //weight: 2
        $x_2_8 = "\\AmigoDistrib.exe" wide //weight: 2
        $x_2_9 = "\\MailRuUpdater.exe" wide //weight: 2
        $x_1_10 = "Update\\UnLoad.exe" wide //weight: 1
        $x_1_11 = "DRIVERS\\BDMWrench_x64.sys" wide //weight: 1
        $x_1_12 = "DRIVERS\\BDEnhanceBoost.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 3 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Torwofun_B_2147693727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Torwofun.B"
        threat_id = "2147693727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Torwofun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "(SystemAutorun|node-webkit|UnLoad|" wide //weight: 4
        $x_4_2 = "\\ShimInclusionList\\amigo.exe" wide //weight: 4
        $x_4_3 = {28 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 7c 00 54 00 6f 00 72 00 20 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 7c 00 43 00 72 00 79 00 70 00 74 00 6f 00 44 00 42 00 7c 00 47 00 65 00 6d 00 57 00 61 00 72 00 65 00 7c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 20 00 41 00 50 00 50 00 [0-16] 29 00 28 00 24 00 7c 00 2f 00 24 00 7c 00 5c 00 5c 00 24 00 29 00}  //weight: 4, accuracy: Low
        $x_2_4 = "\\AmigoDistrib.exe" wide //weight: 2
        $x_1_5 = "DRIVERS\\BDEnhanceBoost.sys" wide //weight: 1
        $x_1_6 = "DRIVERS\\BDMWrench_x64.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

