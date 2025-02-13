rule Trojan_Win32_Mansabo_A_2147725281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mansabo.A!bit"
        threat_id = "2147725281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mansabo"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sc create foundation" ascii //weight: 1
        $x_1_2 = "kernel32::IsDebuggerPresent()i.R0" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mansabo_SM_2147756909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mansabo.SM!MSR"
        threat_id = "2147756909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mansabo"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rr2mP&&UCd3)+Gd" ascii //weight: 1
        $x_1_2 = {8b 44 24 20 8b 08 8b 54 24 14 51 50 68 ?? ?? ?? 00 55 6a 01 55 52 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mansabo_GZM_2147814058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mansabo.GZM!MTB"
        threat_id = "2147814058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mansabo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b 00 66 89 7c 24 48 66 ?? ?? ?? 50 33 00 66 ?? ?? ?? 52 32 00 66 ?? ?? ?? 54 66 ?? ?? ?? 56 66 ?? ?? ?? 5c 66 ?? ?? ?? 1a 66 ?? ?? ?? 1c 66 ?? ?? ?? 22 66 ?? ?? ?? 24 66 ?? ?? ?? 2a 66 ?? ?? ?? 2c 6d 00 66 ?? ?? ?? 2e 73 00 66 ?? ?? ?? 30 76 00 66 ?? ?? ?? 32 63 00 66 ?? ?? ?? 34 66 89 74 24 36 66 89 54 24 38 66 89 4c 24 3a 66 89 5c 24 40}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mansabo_RPX_2147848254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mansabo.RPX!MTB"
        threat_id = "2147848254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mansabo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Inno Setup" wide //weight: 1
        $x_1_2 = "rocksdanister" wide //weight: 1
        $x_1_3 = "Lively Wallpaper" wide //weight: 1
        $x_1_4 = "2.0.6.1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mansabo_NBA_2147930776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mansabo.NBA!MTB"
        threat_id = "2147930776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mansabo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "fHqLSlizClxmHHMSLpJGUSHyTgeFoOzalhKgpxDzoqjwETnDVJyyQAXkcDBPbRmncJaFpaw" ascii //weight: 2
        $x_1_2 = "fJhjZBzUpkvzvfegEKbXXKUjogTEWnjtQvJFODqeJYEYcqRP" ascii //weight: 1
        $x_1_3 = "mFRzsekJpnvrrYWBPUCtFGsFtplRuHKptnlbaGsGdXLTzuFbSHvFmaHB" ascii //weight: 1
        $x_1_4 = "QDvDMdOpvkmxJbDYzNHpHIUlOvAkNuNODsHjqfHewrJbUMootScRK" ascii //weight: 1
        $x_1_5 = "IRyfxKmqwdGMXOrFBFYRwtXetegWWBDLadrMeEAFi" ascii //weight: 1
        $x_1_6 = "btioUXEvcpcPlDQXprwYKLovyIbYEL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

