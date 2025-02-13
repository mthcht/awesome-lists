rule Trojan_Win32_AutoitNuqel_AE_2147795872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitNuqel.AE!MTB"
        threat_id = "2147795872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitNuqel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Latest video shot of infosys girl ftp://tlpoeil:yahoogoogle@ftp.members.lycos.co.uk" ascii //weight: 1
        $x_1_2 = "stream Video of Nayanthara and Simbu  ftp://tlpoeil:yahoogoogle@ftp.members.lycos.co.uk" ascii //weight: 1
        $x_1_3 = "IF PROCESSEXISTS ( \"cmder.exe" ascii //weight: 1
        $x_1_4 = "@SYSTEMDIR & \"\\setup.ini\" , \"Autorun\" , \"Shellexecute\" , \"regsvr\" & \".exe" ascii //weight: 1
        $x_1_5 = "REGDELETE ( \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" , \"BkavFw" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" , \"Shell\" , \"REG_SZ\" , \"Explorer.exe \" & \"regsvr\" & \".exe" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\" , \"Msn Messsenger\" , \"REG_SZ\" , @SYSTEMDIR & \"\\\" & \"regsvr\" & \".exe" ascii //weight: 1
        $x_1_8 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" , \"NofolderOptions\" , \"REG_DWORD\" , 0" ascii //weight: 1
        $x_1_9 = "REGWRITE ( \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" , \"DisableTaskMgr\" , \"REG_DWORD\" , 0" ascii //weight: 1
        $x_1_10 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" , \"DisableRegistryTools\" , \"REG_DWORD\" , 1" ascii //weight: 1
        $x_1_11 = "IF PROCESSEXISTS ( \"game_y.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitNuqel_NLQ_2147797678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitNuqel.NLQ!MTB"
        threat_id = "2147797678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitNuqel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REGWRITE ( \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" , \"HideFileExt\" , \"reg_dword\" , 1 )" ascii //weight: 1
        $x_1_2 = "REGWRITE ( \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" , \"SuperHidden\" , \"reg_dword\" , 1 )" ascii //weight: 1
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" , \"ShowSuperHidden\" , \"REG_DWORD\" , 0 )" ascii //weight: 1
        $x_1_4 = "COPY ( @SCRIPTFULLPATH , @SYSTEMDIR & \"\\system.exe" ascii //weight: 1
        $x_1_5 = "RUNFILE ( @WINDOWSDIR & \"\\svhost.exe" ascii //weight: 1
        $x_1_6 = "IF NOT FILEEXISTS ( @STARTUPDIR & \"\\explore.exe\" ) THEN _RUNDOS ( @SYSTEMDIR & \"\\system.exe copy\" & @STARTUPDIR & \"\\startup.exe" ascii //weight: 1
        $x_1_7 = "IECREATE ( \"http://infikuje.freevnn.com/aa.txt" ascii //weight: 1
        $x_1_8 = "= RANDOM ( 2 , 21 )" ascii //weight: 1
        $x_1_9 = "COPY ( @SYSTEMDIR & \"\\cmd.exe\" , @SYSTEMDIR & \"\\commander.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

