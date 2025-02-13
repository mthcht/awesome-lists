rule VirTool_WinNT_Bancos_DQ_2147618307_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Bancos.DQ"
        threat_id = "2147618307"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "445"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "OnUnload called" ascii //weight: 100
        $x_100_2 = "DriverEntry called" ascii //weight: 100
        $x_100_3 = "RSDS:" ascii //weight: 100
        $x_100_4 = "ZwDeleteFile" ascii //weight: 100
        $x_20_5 = "\\Device\\HarddiskVolume1\\Program Files\\GbPlugin" wide //weight: 20
        $x_20_6 = "\\Device\\HarddiskVolume1\\Arquivos de Programas\\GbPlugin" wide //weight: 20
        $x_1_7 = "\\gbpsv.exe" wide //weight: 1
        $x_1_8 = "\\gbieh.dll" wide //weight: 1
        $x_1_9 = "\\gbpdist.dll" wide //weight: 1
        $x_1_10 = "\\gbieh.gmd" wide //weight: 1
        $x_1_11 = "\\bb.gpc" wide //weight: 1
        $x_1_12 = "\\abn.gpc" wide //weight: 1
        $x_1_13 = "\\cef.gpc" wide //weight: 1
        $x_1_14 = "\\gbiehabn.dll" wide //weight: 1
        $x_1_15 = "\\gbiehcef.dll" wide //weight: 1
        $x_1_16 = "\\gbiehisg.dll" wide //weight: 1
        $x_1_17 = "\\isg.gpc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 2 of ($x_20_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Bancos_A_2147629101_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Bancos.A"
        threat_id = "2147629101"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 10 00 00 6a 00 6a 04 6a 00 6a 00 8d 4d ?? 51 8d 95 ?? ff ff ff 52 68 00 00 01 00 8d 85 ?? ff ff ff 50 ff 15 ?? ?? ?? ?? 89 85 ?? ff ff ff 83 bd ?? ff ff ff 00 7c 0d 8b 8d ?? ff ff ff 51 ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = "\\??\\C:\\Program Files\\Windows Live Toolbar\\msntb.dll" wide //weight: 1
        $x_1_3 = "\\??\\C:\\Program Files\\ScPad\\scpLIB.dll" wide //weight: 1
        $x_1_4 = "\\??\\C:\\Program Files\\GbPlugin\\gbpdist.dll" wide //weight: 1
        $x_1_5 = "\\??\\C:\\Windows\\system32\\drivers\\gbpkm.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

