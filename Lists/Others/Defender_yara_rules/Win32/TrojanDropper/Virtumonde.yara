rule TrojanDropper_Win32_Virtumonde_A_2147800887_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Virtumonde.A"
        threat_id = "2147800887"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Virtumonde"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "93"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "bin;bas;bak;cab;cat;cmd;com;cr;c;drv;db;disk;dll;dns;dos;doc;dvd;eula;exp;fax;font;ftp" ascii //weight: 50
        $x_2_2 = "\\addins\\*.*" ascii //weight: 2
        $x_2_3 = "\\AppPatch\\*.*" ascii //weight: 2
        $x_2_4 = "\\Config\\*.*" ascii //weight: 2
        $x_2_5 = "\\Cursors\\*.*" ascii //weight: 2
        $x_2_6 = "\\Driver Cache\\*.*" ascii //weight: 2
        $x_2_7 = "\\Drivers\\*.*" ascii //weight: 2
        $x_2_8 = "\\Fonts\\*.*" ascii //weight: 2
        $x_2_9 = "\\Help\\*.*" ascii //weight: 2
        $x_2_10 = "\\inf\\*.* " ascii //weight: 2
        $x_2_11 = "\\java\\*.*" ascii //weight: 2
        $x_2_12 = "\\Microsoft.NET\\*.*" ascii //weight: 2
        $x_2_13 = "\\msagent\\*.*" ascii //weight: 2
        $x_2_14 = "\\Registration\\*.*" ascii //weight: 2
        $x_2_15 = "\\security\\*.*" ascii //weight: 2
        $x_2_16 = "\\ServicePackFiles\\*.*" ascii //weight: 2
        $x_2_17 = "\\Speech\\*.*" ascii //weight: 2
        $x_2_18 = "\\system\\*.*" ascii //weight: 2
        $x_2_19 = "\\system32\\*.*" ascii //weight: 2
        $x_2_20 = "\\Web\\*.*" ascii //weight: 2
        $x_2_21 = "\\Windows Update Setup Files\\*.*" ascii //weight: 2
        $x_2_22 = "\\Microsoft\\*.*" ascii //weight: 2
        $x_1_23 = "bush_ssevent" ascii //weight: 1
        $x_1_24 = "klinton_ssmmf" ascii //weight: 1
        $x_1_25 = "salan_ssmutant" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 20 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_50_*) and 21 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Virtumonde_A_2147800887_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Virtumonde.A"
        threat_id = "2147800887"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Virtumonde"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://203.199.200.61" ascii //weight: 2
        $x_2_2 = "expires = Sat, 04-Jun-2005 00:00:00 GMT" ascii //weight: 2
        $x_2_3 = {41 73 79 6e 63 68 72 6f 6e 6f 75 73 00 00 00 00 44 6c 6c 4e 61 6d 65 00 49 6d 70 65 72 73 6f 6e 61 74 65 00 4c 6f 67 6f 66 66 00 00 4c 6f 67 6f 6e 00 00 00 53 79 73 4c 6f 67 6f 6e}  //weight: 2, accuracy: High
        $x_2_4 = "(CAMPAIGNSELECTION" ascii //weight: 2
        $x_2_5 = "PopupsPerDay field is missing" ascii //weight: 2
        $x_2_6 = "LastPopupShown=%s;PopupsShown=%i;MaxPopupPerDay=%i" ascii //weight: 2
        $x_1_7 = {53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00 5c 68 6f 73 74 73}  //weight: 1, accuracy: High
        $x_1_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {2e 62 61 6b 00 00 00 00 2e 62 61 6b 32 00 00 00 2e 62 61 6b 31 00 00 00 2e 69 6e 69 32 00 00 00 2e 74 6d 70 32 00 00 00 2e 74 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

