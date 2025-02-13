rule Virus_Win32_Benci_2147819710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Benci!MTB"
        threat_id = "2147819710"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Benci"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WINKILL ( \"zonealarm\" )" ascii //weight: 1
        $x_1_2 = "WINKILL ( \"Symantec\" )" ascii //weight: 1
        $x_1_3 = "WINKILL ( \"McAfee\" )" ascii //weight: 1
        $x_1_4 = "WINKILL ( \"norton\" )" ascii //weight: 1
        $x_1_5 = "WINKILL ( \"avast\" )" ascii //weight: 1
        $x_1_6 = "WINKILL ( \"Panda\" )" ascii //weight: 1
        $x_1_7 = "WINKILL ( \"Kaspersky\" )" ascii //weight: 1
        $x_1_8 = "WINKILL ( \"bitdefender\" )" ascii //weight: 1
        $x_1_9 = "WINKILL ( \"nod32\" )" ascii //weight: 1
        $x_1_10 = "WINKILL ( \"firewall\" )" ascii //weight: 1
        $x_1_11 = "WINKILL ( \"policy\" )" ascii //weight: 1
        $x_1_12 = "WINKILL ( \"antivirus\" )" ascii //weight: 1
        $x_1_13 = "REGDELETE ( \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" , \"AVP\" )" ascii //weight: 1
        $x_1_14 = "PROCESSCLOSE ( \"avgcc.exe\" )" ascii //weight: 1
        $x_1_15 = "PROCESSCLOSE ( \"avgnt.exe\" )" ascii //weight: 1
        $x_1_16 = "PROCESSCLOSE ( \"ashDisp.exe\" )" ascii //weight: 1
        $x_1_17 = "DisableCMD" ascii //weight: 1
        $x_1_18 = "SFCDisable" ascii //weight: 1
        $x_1_19 = "DisableRegistryTools" ascii //weight: 1
        $x_1_20 = "HideFileExt" ascii //weight: 1
        $x_1_21 = "AntiVirusDisableNotify" ascii //weight: 1
        $x_1_22 = "FirewallDisableNotify" ascii //weight: 1
        $x_1_23 = "UpdatesDisableNotify" ascii //weight: 1
        $x_1_24 = "FirstRunDisabled" ascii //weight: 1
        $x_1_25 = "AntiVirusOverride" ascii //weight: 1
        $x_1_26 = "FirewallOverride" ascii //weight: 1
        $x_1_27 = "DisableSR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

