rule Backdoor_Win32_LimeRat_YA_2147733248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/LimeRat.YA!MTB"
        threat_id = "2147733248"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "LimeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "LimeRAT-Admin" wide //weight: 5
        $x_1_2 = "SbieDll.dll" wide //weight: 1
        $x_1_3 = "vboxhook.dll" wide //weight: 1
        $x_1_4 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_LimeRat_SD_2147745476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/LimeRat.SD!!LimeRat.gen!MTB"
        threat_id = "2147745476"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "LimeRat"
        severity = "Critical"
        info = "LimeRat: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "LimeRAT-Admin" wide //weight: 5
        $x_1_2 = "SbieDll.dll" wide //weight: 1
        $x_1_3 = "vboxhook.dll" wide //weight: 1
        $x_1_4 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

