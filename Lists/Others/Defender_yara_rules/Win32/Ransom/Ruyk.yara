rule Ransom_Win32_Ruyk_A_2147767185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ruyk.A!ibt"
        threat_id = "2147767185"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ruyk"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 7d f4 08 7d 28 8b 45 fc 83 e0 01 74 10 8b 4d fc d1 e9 81 f1 20 83 b8 ed 89 4d f0 eb 08 8b 55 fc d1 ea 89 55 f0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 0c 89 45 ec 8b 4d 0c 83 e9 01 89 4d 0c 83 7d ec 00 74 29 8b 55 08 0f b6 02 33 45 fc 25 ff 00 00 00 8b 4d fc c1 e9 08 33 8c 85 ec fb ff ff 89 4d fc 8b 55 08 83 c2 01 89 55 08 eb c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

