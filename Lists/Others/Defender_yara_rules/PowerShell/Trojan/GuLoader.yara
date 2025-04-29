rule Trojan_PowerShell_GuLoader_RPS_2147940273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/GuLoader.RPS!MTB"
        threat_id = "2147940273"
        type = "Trojan"
        platform = "PowerShell: "
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_10_2 = {3d 00 67 00 63 00 20 00 2d 00 72 00 61 00 77 00 20 00 27 00 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00}  //weight: 10, accuracy: Low
        $x_10_3 = "=gc -raw '%userprofile%\\appdata\\" wide //weight: 10
        $x_10_4 = {2e 00 73 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-12] 2c 00 33 00 29 00 3b 00 2e 00 24 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

