rule TrojanDownloader_Win32_Ulicky_A_2147718629_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ulicky.A!bit"
        threat_id = "2147718629"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulicky"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "36"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RUN ( @COMSPEC & \" /c \" & \"netsh firewall set opmode Disable\" , \"\" , @SW_HIDE )" wide //weight: 1
        $x_1_2 = "RUN ( @COMSPEC & \" /c \" & \"netsh advfirewall set currentprofile state off\" , \"\" , @SW_HIDE )" wide //weight: 1
        $x_1_3 = "RUN ( @COMSPEC & \" /c \" & \"netsh advfirewall set allprofiles state off\" , \"\" , @SW_HIDE )" wide //weight: 1
        $x_10_4 = {49 00 4e 00 49 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 24 00 [0-21] 20 00 2c 00 20 00 22 00 62 00 6f 00 74 00 22 00 20 00 2c 00 20 00 22 00 75 00 72 00 6c 00 22 00 20 00 2c 00 20 00 24 00 [0-21] 20 00 29 00}  //weight: 10, accuracy: Low
        $x_10_5 = {49 00 4e 00 45 00 54 00 47 00 45 00 54 00 20 00 28 00 20 00 24 00 [0-21] 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 24 00 [0-21] 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 10, accuracy: Low
        $x_10_6 = {46 00 49 00 4c 00 45 00 43 00 4f 00 50 00 59 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 [0-21] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 40 00 53 00 54 00 41 00 52 00 54 00 55 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 [0-21] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 10, accuracy: Low
        $x_5_7 = {52 00 55 00 4e 00 57 00 41 00 49 00 54 00 20 00 28 00 20 00 40 00 43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 20 00 26 00 20 00 22 00 20 00 2f 00 63 00 20 00 22 00 20 00 26 00 20 00 22 00 6e 00 65 00 74 00 20 00 76 00 69 00 65 00 77 00 20 00 3e 00 22 00 20 00 26 00 20 00 24 00 [0-21] 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00 20 00 29 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Ulicky_B_2147718630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ulicky.B!bit"
        threat_id = "2147718630"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulicky"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "36"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RUN ( @COMSPEC & \" /c \" & \"netsh firewall set opmode Disable\" , \"\" , @SW_HIDE )" wide //weight: 1
        $x_1_2 = "RUN ( @COMSPEC & \" /c \" & \"netsh advfirewall set currentprofile state off\" , \"\" , @SW_HIDE )" wide //weight: 1
        $x_1_3 = "RUN ( @COMSPEC & \" /c \" & \"netsh advfirewall set allprofiles state off\" , \"\" , @SW_HIDE )" wide //weight: 1
        $x_10_4 = {49 00 4e 00 49 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 24 00 [0-21] 20 00 2c 00 20 00 22 00 62 00 6f 00 74 00 22 00 20 00 2c 00 20 00 22 00 75 00 72 00 6c 00 22 00 20 00 2c 00 20 00 24 00 [0-21] 20 00 29 00}  //weight: 10, accuracy: Low
        $x_10_5 = {49 00 4e 00 45 00 54 00 47 00 45 00 54 00 20 00 28 00 20 00 24 00 [0-21] 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 22 00 20 00 26 00 20 00 24 00 [0-21] 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 10, accuracy: Low
        $x_10_6 = {46 00 49 00 4c 00 45 00 43 00 4f 00 50 00 59 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 [0-21] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 40 00 53 00 54 00 41 00 52 00 54 00 55 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 [0-21] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 10, accuracy: Low
        $x_5_7 = {52 00 55 00 4e 00 20 00 28 00 20 00 22 00 6e 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00 [0-48] 2f 00 65 00 78 00 70 00 69 00 72 00 65 00 73 00 3a 00 6e 00 65 00 76 00 65 00 72 00 20 00 2f 00 61 00 64 00 64 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00 20 00 29 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

