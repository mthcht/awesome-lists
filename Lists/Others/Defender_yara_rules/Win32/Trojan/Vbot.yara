rule Trojan_Win32_Vbot_I_2147645376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbot.I"
        threat_id = "2147645376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Mozilla\\Firefox\\Profiles" wide //weight: 1
        $x_1_2 = "\\dwoneblack.dat" wide //weight: 1
        $x_1_3 = "\\Pharm VB" wide //weight: 1
        $x_1_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 [0-16] 73 00 62 00 74 00 68 00 6f 00 73 00 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = "/contagem.php" wide //weight: 1
        $x_1_6 = "fucker" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Vbot_Q_2147651454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbot.Q"
        threat_id = "2147651454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 45 6d 61 69 6c 73 00 69 44 6f 6e 77 45 78 65 63}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 66 65 63 59 6f 75 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 6f 73 44 61 74 6f 73 5f 4f 4e 00}  //weight: 1, accuracy: High
        $x_1_4 = "Pasw:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vbot_R_2147652849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbot.R"
        threat_id = "2147652849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winmgmts:{impersonationLevel=impersonate}!" wide //weight: 1
        $x_1_2 = "dwoneblack.dat" wide //weight: 1
        $x_1_3 = "\\Downloads\\Pharm VB" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

