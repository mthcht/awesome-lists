rule Ransom_Win32_Laksbades_A_2147712315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Laksbades.A"
        threat_id = "2147712315"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Laksbades"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 8b c6 03 c0 50 8d 45 ?? 8b 0d ?? ?? ?? ?? 8b 93 cc 03 00 00 e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 6a 01 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 8b 45 fc 50 e8 ?? ?? ?? ?? 85 c0 75 03 83 cf ff 8b 45 fc 50 e8}  //weight: 2, accuracy: Low
        $x_1_2 = "\"-key " wide //weight: 1
        $x_1_3 = {2e 00 70 00 68 00 70 00 [0-128] 64 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Laksbades_A_2147712315_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Laksbades.A"
        threat_id = "2147712315"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Laksbades"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "SHAKIM_GAY_RIPPER" wide //weight: 4
        $x_4_2 = "badblock1.exe" wide //weight: 4
        $x_4_3 = "dkpDUVJEV0B5aExGV0pWSkNReXJMS0FKUlZ5ZlBXV0BLUXNAV1ZMSkt5d1BL" wide //weight: 4
        $x_2_4 = "TVFRVR8KClVEXVVEUUZNC1dQCg==" wide //weight: 2
        $x_2_5 = "Help Decrypt.html" wide //weight: 2
        $x_2_6 = "poab.php" wide //weight: 2
        $x_2_7 = "hul.vab" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

