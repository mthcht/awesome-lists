rule MonitoringTool_Win32_FamilyKeylogger_5185_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/FamilyKeylogger"
        threat_id = "5185"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "FamilyKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Family Keylogger 4\\Family Keylogger.lnk" ascii //weight: 3
        $x_5_2 = "mailto:suport@spyarsenal.com?subject=FKL4" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_FamilyKeylogger_5185_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/FamilyKeylogger"
        threat_id = "5185"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "FamilyKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<div class=\"wintitle\">[%02d/%02d/%04d, %02d:%02d].   User: \"%s\".  Window title:\"%s\"</div>" ascii //weight: 1
        $x_1_2 = {63 3a 5c 74 65 6d 70 5c 74 65 6d 70 [0-6] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 05 0c 21 01 10 00 00 00 00 68 c0 a1 00 10 8d 8d 0e 00 80 bd 20 ?? ff ff 0d 75 ?? 83 fb 01 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? fe ff ff 51 ff 15 14 a0 00 10 68 00 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_FamilyKeylogger_5185_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/FamilyKeylogger"
        threat_id = "5185"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "FamilyKeylogger"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sys32V2Contoller" ascii //weight: 1
        $x_3_2 = "-new http://spyarsenal.com/cgi-bin/reg.pl?p=fkl&key=%s&v=%s" ascii //weight: 3
        $x_3_3 = "Family Keylogger v" wide //weight: 3
        $x_5_4 = "<div class=\"wintitle\">[%02d/%02d/%04d, %02d:%02d].   User: \"%s\".  Window title:\"%s\"</div>" ascii //weight: 5
        $x_1_5 = "svcl32.dll" wide //weight: 1
        $x_1_6 = "SysVContoller32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

