rule Trojan_WinNT_Slingshot_A_2147726432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Slingshot.A!dha"
        threat_id = "2147726432"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Slingshot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bf 73 6e 6d 65 57 6a 18 51 ff 15 ?? ?? ?? ?? 8b d8 85 db 75 09 c7 45 fc 9a 00 00 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {7d 14 32 d2 8b ce 89 5e 18 ff 15 ?? ?? ?? ?? 8b c3 e9 ?? ?? 00 00 81 7f 0c 00 20 22 00}  //weight: 2, accuracy: Low
        $x_2_3 = {ff d5 85 c0 74 ?? 83 67 0c 00 83 27 00 89 47 08 53 ff 74 24 20 c7 00 58 89 04 24}  //weight: 2, accuracy: Low
        $x_1_4 = "\\DosDevices\\amxpci" ascii //weight: 1
        $x_1_5 = "\\Device\\amxpci" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

