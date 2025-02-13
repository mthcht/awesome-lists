rule Trojan_MSIL_Remdobe_C_2147681747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remdobe.C"
        threat_id = "2147681747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remdobe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 72 01 00 00 70 72 2b 00 00 70 28 (14|15|16) 00 00 06 (0a 06|0b 07) 28}  //weight: 1, accuracy: Low
        $x_1_2 = {13 04 12 04 20 00 01 00 00 28 12 00 00 06 28 ?? 00 00 0a 72 ?? ?? 00 70 72 2b 00 00 70 28 (14|15|16) 00 00 06 28 ?? 00 00 0a 72 ?? ?? 00 70 72 2b 00 00 70 28 (14|15|16) 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remdobe_D_2147682321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remdobe.D"
        threat_id = "2147682321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remdobe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "--no-submit-stale" wide //weight: 2
        $x_4_2 = "\\System32\\OpenCL.DLL" wide //weight: 4
        $x_9_3 = "http://198.23.167.160/sov1001/coin-miner.exe" wide //weight: 9
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Remdobe_E_2147682322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remdobe.E"
        threat_id = "2147682322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remdobe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "goblmah371z" wide //weight: 1
        $x_1_2 = "--no-submit-stale" wide //weight: 1
        $x_1_3 = {21 2f 00 43 00 20 00 61 00 74 00 74 00 72 00 69 00 62 00 20 00 2d 00 73 00 20 00 2d 00 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

