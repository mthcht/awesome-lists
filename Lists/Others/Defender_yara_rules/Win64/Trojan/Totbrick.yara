rule Trojan_Win64_Totbrick_A_2147719040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Totbrick.A"
        threat_id = "2147719040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Totbrick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 83 c0 41 66 89 04 4b 48 8b 85 98 00 00 00 66 83 3c 43 46}  //weight: 1, accuracy: High
        $x_1_2 = {80 3b 2a 75 06 48 ff c3 48 8b eb 0f b6 03 38 07 74 05 48 8b dd eb}  //weight: 1, accuracy: High
        $x_1_3 = {66 c7 44 24 40 48 b9 66 c7 45 81 48 b8 66 c7 45 8b ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Totbrick_B_2147719041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Totbrick.B"
        threat_id = "2147719041"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Totbrick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 45 af 48 b9 66 c7 45 b9 48 b8 66 c7 45 c3 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {41 03 48 fc 3b d1 72 1c 41 ff c2 49 83 c0 28 45 3b d3 7c e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Totbrick_C_2147719656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Totbrick.C"
        threat_id = "2147719656"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Totbrick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 7c 24 50 71 8b fb 74 4e 85 c0 75 4a 83 ff 64 7d 45}  //weight: 1, accuracy: High
        $x_1_2 = {41 ff c0 80 38 00 75 f4 41 8d 40 ff 3d 02 01 00 00 77 12}  //weight: 1, accuracy: High
        $x_1_3 = "\\\\.\\pipe\\pidplacesomepipe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Totbrick_D_2147719657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Totbrick.D"
        threat_id = "2147719657"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Totbrick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 67 72 6f 75 70 00 00 64 69 6e 6a 00 00 00 00 6c 6d 00 00 68 6c 00 00 73 71 00 00 70 72 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 69 6e 6a 00 00 00 00 73 72 76 00 6d 6d 00 00 73 6d 00 00 6e 68 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 63 c9 48 2b c2 48 c1 f8 05 48 3b c8 73 15 48 c1 e1 05 48 03 ca 48 83 79 18 10 72 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Totbrick_E_2147722880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Totbrick.E"
        threat_id = "2147722880"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Totbrick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MACHINE IN DOMAIN****" wide //weight: 1
        $x_1_2 = "LDAP://%ls" wide //weight: 1
        $x_1_3 = "%s - NOT VULNERABLE" wide //weight: 1
        $x_1_4 = ").DownloadFile('http://" ascii //weight: 1
        $x_1_5 = {4d 61 63 68 69 6e 65 46 69 6e 64 65 72 00 6e 65 74 73 63 61 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Totbrick_H_2147726886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Totbrick.H"
        threat_id = "2147726886"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Totbrick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b9 66 c7 44 24 ?? 48 b8 66 c7 44 24 ?? ff e0 4c 89 74 24 ?? 4c 89 6c 24 ?? 48 c7 44 24 ?? 16 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 07 5a 49 50 41}  //weight: 1, accuracy: High
        $x_1_3 = {6d 63 63 6f 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_4 = {76 65 72 00 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_5 = {67 74 61 67 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_6 = {73 65 72 76 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_7 = {61 75 74 6f 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_8 = {72 75 6e 00 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_9 = {41 81 3e 73 00 54 00 75 17 41 81 7e 04 61 00 72 00}  //weight: 1, accuracy: High
        $x_1_10 = {41 81 3e 73 00 74 00 75 11 41 81 7e 04 41 00 72 00}  //weight: 1, accuracy: High
        $x_1_11 = {32 c2 ff cb 88 45 ?? 85 db 7e}  //weight: 1, accuracy: Low
        $x_1_12 = {4c 8d 44 1b fc 66 41 83 3c 10 33 75 08 66 83 7c 5a fe 32 74 10 66 41 83 3c 10 36 75 1b 66 83 7c 5a fe 34}  //weight: 1, accuracy: High
        $x_1_13 = {08 02 00 00 c7 45 ?? 10 66 00 00}  //weight: 1, accuracy: Low
        $x_1_14 = "\\\\.\\pipe\\pidplacesomepipe" ascii //weight: 1
        $x_1_15 = "\\Release\\GetSystemInfo.pdb" ascii //weight: 1
        $x_1_16 = "<moduleconfig>" ascii //weight: 1
        $x_1_17 = "<autostart>no</autostart>" ascii //weight: 1
        $x_1_18 = "<autostart>yes</autostart>" ascii //weight: 1
        $x_1_19 = {3c 73 79 73 74 65 6d 69 6e 66 6f 3e 0d 0a 3c 67 65 6e 65 72 61 6c 3e 0d 0a 3c 6f 73 3e 4d 69 63 72 6f 73 6f 66 74}  //weight: 1, accuracy: High
        $x_1_20 = {47 42 3c 2f 72 61 6d 3e 0d 0a 3c 2f 67 65 6e 65 72 61 6c 3e 0d 0a 3c 75 73 65 72 73 3e 0d 0a 3c 75 73 65 72 3e}  //weight: 1, accuracy: High
        $x_1_21 = "<needinfo name=\"id\"/>" ascii //weight: 1
        $x_1_22 = "<needinfo name=\"ip\"/>" ascii //weight: 1
        $x_1_23 = "<conf ctl=\"dinj\" file=\"dinj\" period=\"20\"/>" ascii //weight: 1
        $x_1_24 = "<conf ctl=\"sinj\" file=\"sinj\" period=\"20\"/>" ascii //weight: 1
        $x_1_25 = "<conf ctl=\"dpost\" file=\"dpost\" period=\"60\"/>" ascii //weight: 1
        $x_1_26 = "<conf ctl=\"SetConf\" file=\"mailconf\" period=\"90\"/>" ascii //weight: 1
        $x_1_27 = {2d 2d 25 53 0d 0a 43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 6c 69 73 74 22}  //weight: 1, accuracy: High
        $x_1_28 = "s-ng already running" ascii //weight: 1
        $x_1_29 = "s-ng is not running" ascii //weight: 1
        $x_1_30 = "client_id error" ascii //weight: 1
        $x_1_31 = "client ip address error" ascii //weight: 1
        $x_2_32 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 2, accuracy: High
        $x_1_33 = "%S|%S|%S" ascii //weight: 1
        $x_1_34 = "Chrome history db cop" ascii //weight: 1
        $x_1_35 = "Chrome history db should be copied" ascii //weight: 1
        $x_1_36 = "Chrome login db cop" ascii //weight: 1
        $x_1_37 = "Chrome login db should be copied" ascii //weight: 1
        $x_1_38 = "Skip Chrome login db copy" ascii //weight: 1
        $x_1_39 = "Skip Chrome history db copy" ascii //weight: 1
        $x_1_40 = {00 73 79 73 74 65 6d 69 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_41 = {00 69 6e 6a 65 63 74 44 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_42 = "/ser0417/" ascii //weight: 1
        $x_1_43 = "/5/sinj/" ascii //weight: 1
        $x_1_44 = "/injectDll/VERS/browser/" ascii //weight: 1
        $x_1_45 = "%s/%s/%s/send/" ascii //weight: 1
        $x_1_46 = {53 65 72 76 65 72 00 52 65 74 72 79 2d 41 66 74 65 72 00 50 72 6f 78 79 2d 53 75 70 70 6f 72 74 00 50 72 6f 78 79 2d 41 75 74 68 65 6e 74 69 63 61 74 65}  //weight: 1, accuracy: High
        $x_1_47 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0" ascii //weight: 1
        $x_1_48 = "Content-Type: multipart/form-data; boundary=------Boundary0027" ascii //weight: 1
        $x_1_49 = "_configs\\dinj" ascii //weight: 1
        $x_1_50 = "_configs\\sinj" ascii //weight: 1
        $x_1_51 = "_configs\\dpost" ascii //weight: 1
        $x_1_52 = "_configs\\mailconf" ascii //weight: 1
        $x_1_53 = "\\Modules\\systeminfo" ascii //weight: 1
        $x_1_54 = "\\Modules\\injectDll" ascii //weight: 1
        $x_1_55 = "\\Modules\\mailsearcher" ascii //weight: 1
        $x_1_56 = "\\Modules\\importdll" ascii //weight: 1
        $x_1_57 = "\\Modules\\sharedll" ascii //weight: 1
        $x_1_58 = "\\Modules\\tabdll" ascii //weight: 1
        $x_1_59 = "\\Modules\\wormdll" ascii //weight: 1
        $x_1_60 = "\\Modules\\modsysteminfo" ascii //weight: 1
        $x_1_61 = {3c 73 79 73 74 65 6d 69 6e 66 6f 3e 0d 0a 25 73 25 73 25 73 25 73 3c 2f 73 79 73 74 65 6d 69 6e 66 6f 3e}  //weight: 1, accuracy: High
        $x_1_62 = {3c 67 65 6e 65 72 61 6c 3e 0d 0a 25 73 25 73 25 73 3c 2f 67 65 6e 65 72 61 6c 3e}  //weight: 1, accuracy: High
        $x_1_63 = "<os>%s %s %s</os>" ascii //weight: 1
        $x_1_64 = "hDe+bZ8IYt5d" ascii //weight: 1
        $x_1_65 = "rGZ+Jb9FlOAr" ascii //weight: 1
        $x_1_66 = "l8OKE/l9Y8oH" ascii //weight: 1
        $x_1_67 = "n/akop90dpCu" ascii //weight: 1
        $x_1_68 = "n/ANoS3PY896" ascii //weight: 1
        $x_1_69 = "tOU7tSP7tSlG" ascii //weight: 1
        $x_1_70 = "O1tNy8Om4paK" ascii //weight: 1
        $x_1_71 = "rSa/oGoNE8OV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Totbrick_H_2147726887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Totbrick.H!!Totbrick.gen!A"
        threat_id = "2147726887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Totbrick"
        severity = "Critical"
        info = "Totbrick: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b9 66 c7 44 24 ?? 48 b8 66 c7 44 24 ?? ff e0 4c 89 74 24 ?? 4c 89 6c 24 ?? 48 c7 44 24 ?? 16 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 07 5a 49 50 41}  //weight: 1, accuracy: High
        $x_1_3 = {6d 63 63 6f 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_4 = {76 65 72 00 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_5 = {67 74 61 67 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_6 = {73 65 72 76 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_7 = {61 75 74 6f 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_8 = {72 75 6e 00 03 00 81 7d}  //weight: 1, accuracy: Low
        $x_1_9 = {41 81 3e 73 00 54 00 75 17 41 81 7e 04 61 00 72 00}  //weight: 1, accuracy: High
        $x_1_10 = {41 81 3e 73 00 74 00 75 11 41 81 7e 04 41 00 72 00}  //weight: 1, accuracy: High
        $x_1_11 = {32 c2 ff cb 88 45 ?? 85 db 7e}  //weight: 1, accuracy: Low
        $x_1_12 = {4c 8d 44 1b fc 66 41 83 3c 10 33 75 08 66 83 7c 5a fe 32 74 10 66 41 83 3c 10 36 75 1b 66 83 7c 5a fe 34}  //weight: 1, accuracy: High
        $x_1_13 = {08 02 00 00 c7 45 ?? 10 66 00 00}  //weight: 1, accuracy: Low
        $x_1_14 = "\\\\.\\pipe\\pidplacesomepipe" ascii //weight: 1
        $x_1_15 = "\\Release\\GetSystemInfo.pdb" ascii //weight: 1
        $x_1_16 = "<moduleconfig>" ascii //weight: 1
        $x_1_17 = "<autostart>no</autostart>" ascii //weight: 1
        $x_1_18 = "<autostart>yes</autostart>" ascii //weight: 1
        $x_1_19 = {3c 73 79 73 74 65 6d 69 6e 66 6f 3e 0d 0a 3c 67 65 6e 65 72 61 6c 3e 0d 0a 3c 6f 73 3e 4d 69 63 72 6f 73 6f 66 74}  //weight: 1, accuracy: High
        $x_1_20 = {47 42 3c 2f 72 61 6d 3e 0d 0a 3c 2f 67 65 6e 65 72 61 6c 3e 0d 0a 3c 75 73 65 72 73 3e 0d 0a 3c 75 73 65 72 3e}  //weight: 1, accuracy: High
        $x_1_21 = "<needinfo name=\"id\"/>" ascii //weight: 1
        $x_1_22 = "<needinfo name=\"ip\"/>" ascii //weight: 1
        $x_1_23 = "<conf ctl=\"dinj\" file=\"dinj\" period=\"20\"/>" ascii //weight: 1
        $x_1_24 = "<conf ctl=\"sinj\" file=\"sinj\" period=\"20\"/>" ascii //weight: 1
        $x_1_25 = "<conf ctl=\"dpost\" file=\"dpost\" period=\"60\"/>" ascii //weight: 1
        $x_1_26 = "<conf ctl=\"SetConf\" file=\"mailconf\" period=\"90\"/>" ascii //weight: 1
        $x_1_27 = {2d 2d 25 53 0d 0a 43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 6c 69 73 74 22}  //weight: 1, accuracy: High
        $x_1_28 = "s-ng already running" ascii //weight: 1
        $x_1_29 = "s-ng is not running" ascii //weight: 1
        $x_1_30 = "client_id error" ascii //weight: 1
        $x_1_31 = "client ip address error" ascii //weight: 1
        $x_2_32 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 2, accuracy: High
        $x_1_33 = "%S|%S|%S" ascii //weight: 1
        $x_1_34 = "Chrome history db cop" ascii //weight: 1
        $x_1_35 = "Chrome history db should be copied" ascii //weight: 1
        $x_1_36 = "Chrome login db cop" ascii //weight: 1
        $x_1_37 = "Chrome login db should be copied" ascii //weight: 1
        $x_1_38 = "Skip Chrome login db copy" ascii //weight: 1
        $x_1_39 = "Skip Chrome history db copy" ascii //weight: 1
        $x_1_40 = {00 73 79 73 74 65 6d 69 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_41 = {00 69 6e 6a 65 63 74 44 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_42 = "/ser0417/" ascii //weight: 1
        $x_1_43 = "/5/sinj/" ascii //weight: 1
        $x_1_44 = "/injectDll/VERS/browser/" ascii //weight: 1
        $x_1_45 = "%s/%s/%s/send/" ascii //weight: 1
        $x_1_46 = {53 65 72 76 65 72 00 52 65 74 72 79 2d 41 66 74 65 72 00 50 72 6f 78 79 2d 53 75 70 70 6f 72 74 00 50 72 6f 78 79 2d 41 75 74 68 65 6e 74 69 63 61 74 65}  //weight: 1, accuracy: High
        $x_1_47 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0" ascii //weight: 1
        $x_1_48 = "Content-Type: multipart/form-data; boundary=------Boundary0027" ascii //weight: 1
        $x_1_49 = "_configs\\dinj" ascii //weight: 1
        $x_1_50 = "_configs\\sinj" ascii //weight: 1
        $x_1_51 = "_configs\\dpost" ascii //weight: 1
        $x_1_52 = "_configs\\mailconf" ascii //weight: 1
        $x_1_53 = "\\Modules\\systeminfo" ascii //weight: 1
        $x_1_54 = "\\Modules\\injectDll" ascii //weight: 1
        $x_1_55 = "\\Modules\\mailsearcher" ascii //weight: 1
        $x_1_56 = "\\Modules\\importdll" ascii //weight: 1
        $x_1_57 = "\\Modules\\sharedll" ascii //weight: 1
        $x_1_58 = "\\Modules\\tabdll" ascii //weight: 1
        $x_1_59 = "\\Modules\\wormdll" ascii //weight: 1
        $x_1_60 = "\\Modules\\modsysteminfo" ascii //weight: 1
        $x_1_61 = {3c 73 79 73 74 65 6d 69 6e 66 6f 3e 0d 0a 25 73 25 73 25 73 25 73 3c 2f 73 79 73 74 65 6d 69 6e 66 6f 3e}  //weight: 1, accuracy: High
        $x_1_62 = {3c 67 65 6e 65 72 61 6c 3e 0d 0a 25 73 25 73 25 73 3c 2f 67 65 6e 65 72 61 6c 3e}  //weight: 1, accuracy: High
        $x_1_63 = "<os>%s %s %s</os>" ascii //weight: 1
        $x_1_64 = "hDe+bZ8IYt5d" ascii //weight: 1
        $x_1_65 = "rGZ+Jb9FlOAr" ascii //weight: 1
        $x_1_66 = "l8OKE/l9Y8oH" ascii //weight: 1
        $x_1_67 = "n/akop90dpCu" ascii //weight: 1
        $x_1_68 = "n/ANoS3PY896" ascii //weight: 1
        $x_1_69 = "tOU7tSP7tSlG" ascii //weight: 1
        $x_1_70 = "O1tNy8Om4paK" ascii //weight: 1
        $x_1_71 = "rSa/oGoNE8OV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

