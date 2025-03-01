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

