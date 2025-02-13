rule Trojan_Win32_Sysn_EB_2147839732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sysn.EB!MTB"
        threat_id = "2147839732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sysn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "se'duis" ascii //weight: 1
        $x_1_2 = "avilirent de'boute'" ascii //weight: 1
        $x_1_3 = "Diversifying1" ascii //weight: 1
        $x_1_4 = "afterburner" ascii //weight: 1
        $x_1_5 = "Blacklisting" ascii //weight: 1
        $x_1_6 = "bookplates" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "DllFunctionCall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sysn_EM_2147900685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sysn.EM!MTB"
        threat_id = "2147900685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sysn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Brutter swipy unace\\Tracing\\Gobie" ascii //weight: 1
        $x_1_2 = "SubFolderName\\Quotation.scr" ascii //weight: 1
        $x_1_3 = "VB.Clipboard" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "Abatage.Mealberr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

