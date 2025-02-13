rule Trojan_MSIL_Samas_A_2147709840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Samas.A"
        threat_id = "2147709840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 41 4d 5c 6f 72 69 67 69 6e 61 6c 5c 64 65 6c 66 69 6c 65 74 79 70 65 5c 64 65 6c 66 69 6c 65 74 79 70 65 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 64 65 6c 66 69 6c 65 74 79 70 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = "$3dcf8e41-99e7-4167-a8f7-1b89f3f55cb4" ascii //weight: 1
        $x_1_3 = "Microsoft Del Update" ascii //weight: 1
        $x_1_4 = "recursivegetfiles" ascii //weight: 1
        $x_2_5 = {74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 [0-4] 2f 00 76 00 20 00 2f 00 66 00 6f 00 20 00 63 00 73 00 76 00 [0-16] 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 [0-6] 2f 00 66 00 20 00 2f 00 70 00 69 00 64 00}  //weight: 2, accuracy: Low
        $x_2_6 = {73 00 70 00 69 00 [0-4] 73 00 70 00 66 00 [0-4] 73 00 61 00 76 00 [0-4] 73 00 69 00 6b 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Samas_B_2147710147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Samas.B"
        threat_id = "2147710147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "2E00610063002C002E006200610063006B002C002E006200610063006B00750070002C" wide //weight: 2
        $x_2_2 = "6B006C0069007300740020002F004E00480020002F00460049002000220049004D004100470045004E0041004D0045002000650071" wide //weight: 2
        $x_1_3 = "<rec_ur_siiiiv_eeeg__etfielll__>b__0" ascii //weight: 1
        $x_2_4 = "$3dcf8e41-99e7-4167-a8f7-1b89f3f55cb4" ascii //weight: 2
        $x_1_5 = "\\Release\\gogodele.pdb" ascii //weight: 1
        $x_1_6 = "\\MicroPrinter" wide //weight: 1
        $x_1_7 = "\\Release\\dilito.pdb" ascii //weight: 1
        $x_2_8 = {5c 53 41 4d 5c 4f 72 69 67 69 6e 61 6c 5c 64 65 6c 66 69 6c 65 74 79 70 65 5c 64 65 6c 66 69 6c 65 74 79 70 65 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c [0-15] 2e 70 64 62}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Samas_C_2147712017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Samas.C"
        threat_id = "2147712017"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "$3dcf8e41-99e7-4167-a8f7-1b89f3f55cb4" ascii //weight: 3
        $x_2_2 = "\\Release\\dilito.pdb" ascii //weight: 2
        $x_2_3 = {5c 53 41 4d 5c 4f 72 69 67 69 6e 61 6c 5c 64 65 6c 66 69 6c 65 74 79 70 65 5c 64 65 6c 66 69 6c 65 74 79 70 65 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c [0-15] 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_1_4 = {63 68 65 65 65 65 6b 6b 6b 6b 6b 6b 69 66 66 66 66 66 61 70 72 6f 63 63 63 63 65 65 65 65 5f 69 73 5f 6f 70 6e 6e 6e 6e 6e 6e 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = "<finddddd_recursssss_filesssssss_in_drrrrrrrivvvvvvvesss>" ascii //weight: 1
        $x_1_6 = "\\UpgradeWindows" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Samas_A_2147756884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Samas.A!MTB"
        threat_id = "2147756884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Samas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide //weight: 10
        $x_10_2 = "/c schtasks /create /f /sc onlogon /rl highest /tn" wide //weight: 10
        $x_1_3 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_4 = "RSACryptoServiceProvider" ascii //weight: 1
        $x_1_5 = "%AppData%" wide //weight: 1
        $x_1_6 = "Pastebin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

