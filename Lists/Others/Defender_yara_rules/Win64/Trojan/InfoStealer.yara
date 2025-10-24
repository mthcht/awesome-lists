rule Trojan_Win64_InfoStealer_NI_2147923389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.NI!MTB"
        threat_id = "2147923389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 15 ea 19 04 00 48 89 0c 24 44 0f 11 7c 24 08 48 89 54 24 18 48 89 44 24 20 44 0f 11 7c 24 28 e8 ?? ?? ?? ?? 45 0f 57 ff 4c 8b 35 00 50 9d 00}  //weight: 3, accuracy: Low
        $x_1_2 = "portgetaddrinfowtransmitfile" ascii //weight: 1
        $x_1_3 = "BitappCoin" ascii //weight: 1
        $x_1_4 = "masterkey_db" ascii //weight: 1
        $x_1_5 = "Fromicmpigmpftpspop3smtpdial" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_InfoStealer_EM_2147955891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InfoStealer.EM!MTB"
        threat_id = "2147955891"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {50 45 00 00 64 86 0f 00 2c 91 4f 66 00 00 00 00 00 00 00 00 f0 00 22 00 0b 02 0e 00 00 4c a5 08}  //weight: 3, accuracy: High
        $x_3_2 = "electron.exe.pdb" ascii //weight: 3
        $x_3_3 = "PDF Editor" ascii //weight: 3
        $x_1_4 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 00 00 31 00 2e 00 30 00 2e 00 38}  //weight: 1, accuracy: High
        $x_1_5 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 00 00 31 00 2e 00 30 00 2e 00 32}  //weight: 1, accuracy: High
        $x_1_6 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 00 00 31 00 2e 00 30 00 2e 00 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

