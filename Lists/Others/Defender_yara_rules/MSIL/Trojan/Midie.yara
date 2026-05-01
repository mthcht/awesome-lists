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

