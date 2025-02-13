rule Trojan_WinNT_Killfiles_R_2147605558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Killfiles.R"
        threat_id = "2147605558"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb e1 8b 45 08 c7 40 34 d0 02 01 00 68 e0 02 01 00 8d 4d ?? 51 e8 ?? ?? ff ff 68 58 03 01 00 8d (55 c4|95 64 ff) 52 e8 ?? ?? ff ff 68 d0 03 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Device\\HarddiskVolume1\\Program Files\\GbPlugin\\" wide //weight: 1
        $x_1_3 = "\\Device\\HarddiskVolume1\\Arquivos de Programas\\GbPlugin\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Killfiles_EU_2147630185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Killfiles.EU"
        threat_id = "2147630185"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {b8 08 20 01 00 ff 30 ff 75 10 ff 15 00 10 01 00 85 c0 59 59 75 14 57 68 04 31 01 00 56 66 89 1c 7e ff 15 18 10 01 00 83 c4 0c ff 45 18 8b 45 18 8d 04 85 08 20 01 00 39 18 75 ca}  //weight: 100, accuracy: High
        $x_1_2 = "xyvz5.flf" wide //weight: 1
        $x_1_3 = "rnzba.flf" wide //weight: 1
        $x_1_4 = "nivcoo.flf" wide //weight: 1
        $x_1_5 = "nitzsk86.flf" wide //weight: 1
        $x_1_6 = "nfjzba2.flf" wide //weight: 1
        $x_1_7 = "klif.sys" wide //weight: 1
        $x_1_8 = "bdvedisk.sys" wide //weight: 1
        $x_1_9 = "avgtdix.sys" wide //weight: 1
        $x_1_10 = "avgldx86.sys" wide //weight: 1
        $x_1_11 = "aswmon.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

