rule SoftwareBundler_Win32_OxyPumper_205134_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/OxyPumper"
        threat_id = "205134"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "OxyPumper"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Usage: updater.exe <appname> <domain> <timeout> <attemptsCount>" wide //weight: 1
        $x_1_2 = "_updater/" wide //weight: 1
        $x_1_3 = "/getdistr/" wide //weight: 1
        $x_1_4 = "HKEY_CURRENT_USER\\SOFTWARE\\Escolade" wide //weight: 1
        $x_1_5 = "File didn't start..." wide //weight: 1
        $x_1_6 = "\\iPumper\\Updater\\Updater\\obj\\x86\\Release\\Updater.pdb" ascii //weight: 1
        $x_2_7 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 73 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5c 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule SoftwareBundler_Win32_OxyPumper_205134_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/OxyPumper"
        threat_id = "205134"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "OxyPumper"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 00 46 00 32 00 37 00 32 00 46 00 34 00 34 00 44 00 46 00 30 00 33 00 34 00 33 00 36 00 39 00 42 00 33 00 31 00 37 00 45 00 33 00 30 00 31 00 30 00 46 00 36 00 44 00 43 00 38 00 31 00 35 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {2d 00 2d 00 64 00 6d 00 6c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 20 00 2d 00 2d 00 75 00 70 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 25 00 73 00 2f 00 61 00 70 00 69 00 2f 00 63 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_2_4 = "<config><guid>%s</guid><affid>%s</affid><keyword>%s</keyword><country>" wide //weight: 2
        $x_1_5 = {25 00 73 00 5f 00 25 00 2e 00 36 00 64 00 2e 00 6c 00 6f 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {44 00 4d 00 55 00 70 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 61 00 6c 00 74 00 42 00 6c 00 61 00 6e 00 6b 00 4e 00 65 00 74 00 32 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_2_8 = {44 00 69 00 73 00 74 00 72 00 69 00 62 00 20 00 68 00 61 00 73 00 20 00 77 00 72 00 6f 00 6e 00 67 00 20 00 73 00 69 00 7a 00 65 00 2e 00 20 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 20 00 3d 00 20 00 25 00 64 00 2e 00 20 00 54 00 72 00 79 00 20 00 61 00 67 00 61 00 69 00 6e 00 2e 00 2e 00 2e 00 00 00}  //weight: 2, accuracy: High
        $x_2_9 = "http://installdream.com/download/blankNet2.dat" wide //weight: 2
        $x_2_10 = "Software\\LADY'S WOOD 2013 LIMITED" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

