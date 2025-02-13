rule Trojan_Win32_Dreammon_B_126581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dreammon.gen!B"
        threat_id = "126581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dreammon"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "HD_Monitor_Hard" wide //weight: 3
        $x_3_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 25 00 73 00 2f 00 25 00 73 00 3f 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 3d 00 25 00 30 00 34 00 64 00 2d 00 25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 20 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00 26 00 67 00 72 00 6f 00 75 00 70 00 3d 00 25 00 73 00 26 00 68 00 6f 00 73 00 74 00 3d 00 25 00 73 00 26 00 6f 00 73 00 76 00 65 00 72 00 3d 00 25 00 73 00 26 00 65 00 6e 00 76 00 76 00 65 00 72 00 3d 00 25 00 73 00 26 00 66 00 75 00 6e 00 76 00 65 00 72 00 3d 00 25 00 73 00 00 00}  //weight: 3, accuracy: High
        $x_3_3 = "target='_self' id='fordreamclick'><br><script defer>fordreamclick.click();" ascii //weight: 3
        $x_1_4 = {69 6e 69 2e 6f 66 66 69 63 65 73 75 70 64 61 74 65 2e 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {69 6e 69 2e 6d 73 6e 6d 65 73 73 65 6e 67 65 72 75 70 64 61 74 65 2e 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {69 6e 69 2e 6f 66 66 69 63 65 32 30 30 35 75 70 64 61 74 65 73 2e 6e 65 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dreammon_C_128404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dreammon.C"
        threat_id = "128404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dreammon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "dream/dream.php" ascii //weight: 10
        $x_10_2 = "http://%s/%s?type=exe&cookie=" ascii //weight: 10
        $x_10_3 = "DreamOnceFunDownPath" ascii //weight: 10
        $x_1_4 = "ini.officesupdate.net" ascii //weight: 1
        $x_1_5 = "ini.office2005updates.net" ascii //weight: 1
        $x_1_6 = "ini.msnmessengerupdate.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dreammon_D_157673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dreammon.D"
        threat_id = "157673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dreammon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {69 6e 69 2e 6f 66 66 69 63 65 73 75 70 64 61 74 65 2e 6e 65 74 00}  //weight: 5, accuracy: High
        $x_5_2 = {69 6e 69 2e 6f 66 66 69 63 65 32 30 30 35 75 70 64 61 74 65 73 2e 6e 65 74 00}  //weight: 5, accuracy: High
        $x_5_3 = {25 73 3f 74 79 70 65 3d 25 73 26 76 65 72 3d 25 73 26 74 69 6d 65 3d 25 64 26 67 72 6f 75 70 3d 25 73 26 70 76 65 72 3d 25 73 26 68 6f 73 74 3d 25 73 00}  //weight: 5, accuracy: High
        $x_1_4 = {68 64 64 5f 73 6d 61 72 74 70 69 70 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {6f 6c 65 73 6d 61 72 74 70 61 72 73 65 2e 78 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {6d 73 73 6d 61 72 74 70 6c 75 67 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_7 = {73 6d 61 72 74 2f 73 6d 61 72 74 6d 61 69 6e 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

