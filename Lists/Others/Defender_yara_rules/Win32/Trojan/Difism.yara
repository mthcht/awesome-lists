rule Trojan_Win32_Difism_2147573101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Difism"
        threat_id = "2147573101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Difism"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a5 a5 a5 6a 10 59 a5 6a 01 89 85}  //weight: 1, accuracy: High
        $x_1_2 = {a5 a5 a5 a5 66 a5 33 f6 83 7b 28 01 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 08 8a 4c 31 08 30 0a 42 fe 00 4f 75 f1}  //weight: 1, accuracy: High
        $x_1_4 = "Software\\GIANTCompany\\AntiSpyware" ascii //weight: 1
        $x_2_5 = "Monitor_IEPlugins_Enabled" ascii //weight: 2
        $x_1_6 = "Firewall\\MpfUi.Dll" ascii //weight: 1
        $x_1_7 = "Pro\\SnortImp.dll" ascii //weight: 1
        $x_1_8 = "Firewall\\Engine.dll" ascii //weight: 1
        $x_1_9 = "ZoneAlarm\\vsruledb.dll" ascii //weight: 1
        $x_2_10 = "FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 2
        $x_2_11 = "CONNECT %s:%d HTTP" ascii //weight: 2
        $x_2_12 = ":*:Enabled:" ascii //weight: 2
        $x_2_13 = "/takeme2/?a=" ascii //weight: 2
        $x_2_14 = {73 6f 75 6e 64 00 00 00 6d 70 33 7a}  //weight: 2, accuracy: High
        $x_2_15 = {64 62 78 00 6d 73 67 00 70 70 74 00 6e 66 6f}  //weight: 2, accuracy: High
        $x_2_16 = {2e 62 69 7a 00 68 74 74 70 3a 2f 2f}  //weight: 2, accuracy: High
        $x_1_17 = "about:blank" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

