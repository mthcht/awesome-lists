rule Trojan_Win32_Sysmaine_A_2147705642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sysmaine.A!dha"
        threat_id = "2147705642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sysmaine"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 dc 4b 4c 00 6a 08 50 89 45 ?? ff d7 8b 4d 0c 8b f0 8b c1 6a 08 5b 99 f7 fb 83 65 ?? 00 2b ca 83 c1 10}  //weight: 3, accuracy: Low
        $x_1_2 = "Control Panel\\International\\Geo\\" wide //weight: 1
        $x_1_3 = "DirUserProfile" wide //weight: 1
        $x_1_4 = "thebat" wide //weight: 1
        $x_1_5 = "netscp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

