rule Trojan_Win32_Dllhijacker_A_2147734618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dllhijacker.A"
        threat_id = "2147734618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dllhijacker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{2DEA658F-54C1-4227-AF9B-260AB5FC3543}" ascii //weight: 1
        $x_1_2 = "\\CLSID\\{2222222222222}\\InprocServer32" ascii //weight: 1
        $x_1_3 = "\\mstracer.dll" ascii //weight: 1
        $x_1_4 = "\\STUDIO\\1059- virus.win.trojan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Dllhijacker_PAA_2147778063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dllhijacker.PAA!MTB"
        threat_id = "2147778063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dllhijacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System\\ControlSet001\\Control\\ComputerName\\Comput" wide //weight: 1
        $x_1_2 = "\"C:\\Windows\\iexplore.exe\"" ascii //weight: 1
        $x_1_3 = "delete /f /tn updatecfgSetup" ascii //weight: 1
        $x_1_4 = "trolC:\\Windows\\updatecfg" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\setup.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dllhijacker_DG_2147816547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dllhijacker.DG!MTB"
        threat_id = "2147816547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dllhijacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 94 0c 64 01 00 00 88 10 41 40 3b cf 72 f1}  //weight: 1, accuracy: High
        $x_1_2 = {35 8c 17 da 28 3b d0 75 05}  //weight: 1, accuracy: High
        $x_1_3 = "c:\\windows\\system32\\mstracer.dll" ascii //weight: 1
        $x_1_4 = "virus.win.trojan\\mantanani_com_hijack" ascii //weight: 1
        $x_1_5 = "CreateMutexW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

