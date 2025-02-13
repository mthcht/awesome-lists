rule Trojan_Win32_Toha_A_2147651434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Toha.A"
        threat_id = "2147651434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Toha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 fe 15 75 10 8b 87 ac 03 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 fe 24 75 10 8b 87 ac 03 00 00 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 fe 3b 75 10 8b 87 ac 03 00 00 ba}  //weight: 2, accuracy: Low
        $x_2_2 = {bb 01 00 00 00 83 fb 64 74 08 81 fb c8 00 00 00 75 17 b8 64 00 00 00 e8}  //weight: 2, accuracy: High
        $x_1_3 = "/unlock.php" wide //weight: 1
        $x_1_4 = "Locating password file..." wide //weight: 1
        $x_1_5 = "Successfully recovered password file..." wide //weight: 1
        $x_1_6 = "Please check your Anti-Virus." wide //weight: 1
        $x_1_7 = "_p_.txt" wide //weight: 1
        $x_1_8 = "www.facebook.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

