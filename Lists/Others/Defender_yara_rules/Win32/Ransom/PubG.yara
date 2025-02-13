rule Ransom_Win32_PubG_A_2147731908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PubG.A!dha"
        threat_id = "2147731908"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PubG"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Your files is encrypred by PUBG Ransomware!" wide //weight: 1
        $x_1_2 = "Your files is encrypred by PUBG Ransomware!" ascii //weight: 1
        $x_2_3 = "C:\\Users\\ryank\\source\\repos\\PUBG_Ransomware\\PUBG_Ransomware\\obj\\Debug\\PUBG_Ransomware.pdb" ascii //weight: 2
        $x_2_4 = {2e 00 33 00 67 00 32 00 00 ?? 2e 00 33 00 67 00 70 00 00 ?? 2e 00 61 00 61 00 66 00 00 ?? 2e 00 61 00 63 00 63 00 64 00 62 00 00 ?? 2e 00 61 00 65 00 70 00 00 ?? 2e 00 61 00 65 00 70 00 78 00 00 ?? 2e 00 61 00 65 00 74 00 00 ?? 2e 00 61 00 69 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

