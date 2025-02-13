rule Virus_Win32_Gesteal_A_2147629836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Gesteal.A"
        threat_id = "2147629836"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Gesteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 41 68 02 00 00 80 8d 87 d4 d2 ff ff ff 10 85 c0 75 2b 8b 1e 8b 4e 08 85 c9 74 17 85 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

