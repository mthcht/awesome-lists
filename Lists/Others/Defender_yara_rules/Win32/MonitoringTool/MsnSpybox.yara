rule MonitoringTool_Win32_MsnSpybox_148855_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/MsnSpybox"
        threat_id = "148855"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MsnSpybox"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "F:\\Super Source\\WT Software\\Progetos\\Msn Spybox" wide //weight: 3
        $x_1_2 = "senhamastermsnspybox" wide //weight: 1
        $x_1_3 = "http://www.wtsoftware.com.br/active/active.php?logon=wtsoftware&user=" wide //weight: 1
        $x_1_4 = "http://www.wtsoftware.com.br/loja/produtos.php?prog=msnspy" ascii //weight: 1
        $x_1_5 = "Software\\Inspybox\\Msn Spybox" wide //weight: 1
        $x_1_6 = "msnspyboxcodigo" wide //weight: 1
        $x_1_7 = "http://www.wtsoftware.com.br/produtos/msnspybox" wide //weight: 1
        $x_1_8 = "Para visualizar o Msn Spybox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

