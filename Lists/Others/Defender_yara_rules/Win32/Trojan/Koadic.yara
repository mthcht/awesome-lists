rule Trojan_Win32_Koadic_A_2147733231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koadic.A!attk"
        threat_id = "2147733231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koadic"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-15] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 [0-48] 52 00 75 00 6e 00 48 00 54 00 4d 00 4c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_3 = "=;\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Koadic_A_2147733231_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koadic.A!attk"
        threat_id = "2147733231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koadic"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 [0-48] 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00}  //weight: 1, accuracy: Low
        $x_1_2 = " /s " wide //weight: 1
        $x_1_3 = " /u " wide //weight: 1
        $x_1_4 = " /n " wide //weight: 1
        $x_1_5 = " /i:http://" wide //weight: 1
        $x_1_6 = {3d 00 3b 00 [0-16] 73 00 63 00 72 00 6f 00 62 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Koadic_A_2147733231_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koadic.A!attk"
        threat_id = "2147733231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koadic"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " javascript:" wide //weight: 1
        $x_1_3 = {5c 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 [0-8] 2c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "RunHTMLApplication" wide //weight: 1
        $x_1_5 = "ActiveXObject(" wide //weight: 1
        $x_1_6 = "Msxml2.ServerXMLHTTP" wide //weight: 1
        $x_1_7 = ".open(" wide //weight: 1
        $x_1_8 = ".send();" wide //weight: 1
        $x_1_9 = "eval(" wide //weight: 1
        $x_1_10 = ".responseText);" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

