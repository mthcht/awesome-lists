rule TrojanSpy_MSIL_Quasar_RB_2147752343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Quasar.RB!MTB"
        threat_id = "2147752343"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT * FROM FirewallProduct" wide //weight: 1
        $x_1_2 = "SELECT * FROM Win32_OperatingSystem WHERE Primary='true'" wide //weight: 1
        $x_1_3 = "del /a /q /f" wide //weight: 1
        $x_1_4 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_5 = "\\FileZilla\\sitemanager.xml" wide //weight: 1
        $x_1_6 = "logins.json" wide //weight: 1
        $x_1_7 = "HandleDoProcessKill" ascii //weight: 1
        $x_1_8 = "HandleGetKeyloggerLogs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Quasar_SL_2147837883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Quasar.SL!MTB"
        threat_id = "2147837883"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "server1.Resources.resources" ascii //weight: 1
        $x_1_2 = "Cllikiom Kfsdggimo Media" ascii //weight: 1
        $x_1_3 = "server1.exe" ascii //weight: 1
        $x_1_4 = "2021 Cllikiom Kfsdggimo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Quasar_ARA_2147896958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Quasar.ARA!MTB"
        threat_id = "2147896958"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Buffer\\obj\\Release\\Michael.pdb" ascii //weight: 2
        $x_2_2 = "ewjufhureuregtih" ascii //weight: 2
        $x_2_3 = "$cef65898-47b6-43d2-b441-07f3cd9c27e4" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Quasar_SN_2147917838_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Quasar.SN!MTB"
        threat_id = "2147917838"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 1d 5d 16 fe 01 13 04 11 04 2c 0b 07 09 07 09 91 1f 4d 61 b4 9c 00 00 09 17 d6 0d 09 08 31 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Quasar_SO_2147927664_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Quasar.SO!MTB"
        threat_id = "2147927664"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 3b 00 00 0a 72 4d 00 00 70 73 3c 00 00 0a 28 3d 00 00 0a 6f 3e 00 00 0a 0c dd 06 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Quasar_SO_2147927664_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Quasar.SO!MTB"
        threat_id = "2147927664"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 6f 27 00 00 0a 18 63 d4 8d 17 00 00 01 13 04 20 00 01 00 00 8d 19 00 00 01 13 05 16 13 07 2b 15}  //weight: 2, accuracy: High
        $x_2_2 = "server.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

