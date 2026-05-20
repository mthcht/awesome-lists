rule Trojan_MSIL_Midie_SX_2147967626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Midie.SX!MTB"
        threat_id = "2147967626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "( STEALER PROCESS )" ascii //weight: 30
        $x_20_2 = "Blocking TaskManager, CMD and Powershell" ascii //weight: 20
        $x_15_3 = "CST.Mutex" ascii //weight: 15
        $x_10_4 = "Couldn't kill the VPN" ascii //weight: 10
        $x_5_5 = "AtomicWallet" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Midie_SXA_2147968171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Midie.SXA!MTB"
        threat_id = "2147968171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {16 7e 01 00 00 04 2d 25 1f 10 d0 13 00 00 01 28 04 00 00 0a d0 02 00 00 02 28 04 00 00 0a 28 0b 00 00 0a 28 10 00 00 0a}  //weight: 30, accuracy: High
        $x_20_2 = {7e 0d 00 00 04 2d 4f 20 00 01 00 00 72 ?? 00 00 70 14 d0 02 00 00 02 28 04 00 00 0a 19 8d 1c 00 00 01 13 ?? 11 ?? 16 16 14 28 15 00 00 0a}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Midie_MCW_2147968631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Midie.MCW!MTB"
        threat_id = "2147968631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 11 08 9a 13 09 11 09 72 a8 00 00 70 28 1a 00 00 0a 2d 10 11 09 72 b6 00 00 70}  //weight: 1, accuracy: High
        $x_1_2 = "Zerologon attack" wide //weight: 1
        $x_1_3 = "SharpZeroLogon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Midie_SXB_2147969755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Midie.SXB!MTB"
        threat_id = "2147969755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {28 6e 00 00 06 0d 09 28 61 00 00 0a 2d 0f 09 28 62 00 00 0a 2c 07 09 28 63 00 00 0a 26 de 03 26 de 00 28 5f 00 00 0a 6f 60 00 00 0a 2a}  //weight: 30, accuracy: High
        $x_10_2 = {28 73 00 00 0a 6f 3d 00 00 0a 28 4a 00 00 06 6f 37 00 00 06 6f bb 00 00 0a 26 20 e8 03 00 00 28 bc 00 00 0a 12 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

