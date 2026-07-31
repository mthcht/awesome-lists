rule Trojan_MSIL_SpyGate_RG_2147893188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyGate.RG!MTB"
        threat_id = "2147893188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 3a 5c 55 73 65 72 73 5c 72 6f 6f 74 30 5c 44 65 73 6b 74 6f 70 5c d8 a7 d9 84 d8 a7 d8 ae d8 aa d8 b1 d8 a7 d9 82 5c 50 72 69 76 61 74 65 5c 73 65 6e 64 20 66 69 6c 65 20 6d 5c 53 65 72 76 65 72 5c 53 65 72 76 65 72 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 53 65 72 76 65 72 2e 70 64 62}  //weight: 1, accuracy: High
        $x_1_2 = "info||myID|" wide //weight: 1
        $x_1_3 = "The File Has Run" wide //weight: 1
        $x_1_4 = "avgnt" wide //weight: 1
        $x_1_5 = "Avira" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyGate_AA_2147962380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyGate.AA!AMTB"
        threat_id = "2147962380"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyGate"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "H21 (h21@exploit.im)" ascii //weight: 1
        $x_1_2 = "h21rdphvnc.pdb" ascii //weight: 1
        $x_1_3 = "5.8.88.233" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyGate_SN_2147975028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyGate.SN!MTB"
        threat_id = "2147975028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {08 02 7b a6 00 00 04 6f c4 01 00 0a 13 09 08 11 09 28 c5 01 00 0a 13 0a 08 16 11 09 02 7b a6 00 00 04 6f f5 00 00 0a d6 6f c6 01 00 0a 0c 02 7b a4 00 00 04 13 0b 11 0b 2c 0a 11 0b 11 0a 6f 6f 01 00 06 00}  //weight: 4, accuracy: High
        $x_2_2 = "5a542c1b-2d36-4c31-b039-26a88d3967da" ascii //weight: 2
        $x_1_3 = "Stub.My.Resources" ascii //weight: 1
        $x_1_4 = "invisible_cursor.cur" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

