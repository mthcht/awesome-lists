rule MonitoringTool_Win32_MsnSpyMaster_159498_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/MsnSpyMaster"
        threat_id = "159498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MsnSpyMaster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{app}\\msmaster.exe" ascii //weight: 1
        $x_1_2 = "Msn SpyMaster" ascii //weight: 1
        $x_1_3 = "Syncsoft Softwares ou seus fornecedores respon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_MsnSpyMaster_159498_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/MsnSpyMaster"
        threat_id = "159498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MsnSpyMaster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Win SpyMaster 2010" ascii //weight: 3
        $x_3_2 = "Msn SpyMaster 2010" wide //weight: 3
        $x_4_3 = "http://www.syncsoft.com.br/es/spyonepro/help/" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_MsnSpyMaster_159498_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/MsnSpyMaster"
        threat_id = "159498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MsnSpyMaster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "syncsoft.com.br\\Projetos\\Msn SpyMaster" wide //weight: 1
        $x_1_2 = "O Msn SpyMaster est" wide //weight: 1
        $x_1_3 = "senhamastermsnspymaster" wide //weight: 1
        $x_1_4 = "es sobre o Msn SpyMaster" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

