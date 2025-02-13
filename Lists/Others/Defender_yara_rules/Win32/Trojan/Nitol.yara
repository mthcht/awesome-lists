rule Trojan_Win32_Nitol_RF_2147842058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nitol.RF!MTB"
        threat_id = "2147842058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Documents\\update.lnk" ascii //weight: 1
        $x_1_2 = "Bensons.pdb" ascii //weight: 1
        $x_2_3 = "http://department.microsoftmiddlename.tk" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nitol_RJ_2147849889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nitol.RJ!MTB"
        threat_id = "2147849889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\jy.lnk" ascii //weight: 1
        $x_1_2 = "F:\\hackshen.exe" ascii //weight: 1
        $x_1_3 = ":9874/AnyDesk.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nitol_RJ_2147849889_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nitol.RJ!MTB"
        threat_id = "2147849889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PREVED! I SMOKE GANJA EVERY DAY!" ascii //weight: 1
        $x_1_2 = "sdcmbxtrgkh2" ascii //weight: 1
        $x_1_3 = "pvtfntnrxvmscphkgbftd_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nitol_RJ_2147849889_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nitol.RJ!MTB"
        threat_id = "2147849889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://154.211.14.91/word.exe" wide //weight: 1
        $x_1_2 = "WindowsProject8.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nitol_A_2147896410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nitol.A!MTB"
        threat_id = "2147896410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 3a 34 ?? 04 ?? 88 04 3a 42 3b d1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nitol_RPZ_2147904758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nitol.RPZ!MTB"
        threat_id = "2147904758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e9 54 ca 00 00 20 68 f8 4c 42 00 68 01 01 00 00 e8 e6 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nitol_B_2147909115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nitol.B!MTB"
        threat_id = "2147909115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 ff c5 f8 49 d1 c5 44 3b d9 41 f6 c1 ?? 49 81 c5 ?? ?? ?? ?? 80 fd ?? 49 81 f5 ?? ?? ?? ?? f5 4d 33 f5 f5 41}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

