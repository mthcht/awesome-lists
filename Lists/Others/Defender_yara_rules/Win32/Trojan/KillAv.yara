rule Trojan_Win32_KillAv_YA_2147733369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KillAv.YA!MTB"
        threat_id = "2147733369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KillAv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "schtasks /create /sc minute /mo" wide //weight: 5
        $x_5_2 = "CreateShortcut" wide //weight: 5
        $x_5_3 = "WScript.Shell" wide //weight: 5
        $x_1_4 = "\\Avast\\avastUI.exe" wide //weight: 1
        $x_1_5 = "\\AVG\\Antivirus\\AVGUI.exe" wide //weight: 1
        $x_1_6 = "\\KasperSky Lab\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

