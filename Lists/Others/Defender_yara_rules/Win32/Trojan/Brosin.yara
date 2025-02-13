rule Trojan_Win32_Brosin_A_2147798093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brosin.A!dha"
        threat_id = "2147798093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brosin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 6f 6d 53 70 65 63 00 20 3e 3e 20 4e 55 4c 00 2f 63 20 64 65 6c 20 00}  //weight: 2, accuracy: High
        $x_1_2 = "EBETFYBYAGJK" ascii //weight: 1
        $x_1_3 = "EABGFHDCEQGGDCDTCTDVFJIGHHBEBCGBJU" ascii //weight: 1
        $x_1_4 = "Unknow CPU" ascii //weight: 1
        $x_2_5 = {8a 02 b1 1a f6 e9 8a 4a 01 8b fd 02 c1 83 c9 ff 04 25 83 c2 02 88 44 34 ?? 33 c0 46}  //weight: 2, accuracy: Low
        $x_2_6 = {8b fd 8d 0c 40 c1 e1 04 2b c8 8d 0c 49 8d 0c 89 8d 0c c9 8d 04 48 83 c9 ff 2b d8 33 c0 42}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

