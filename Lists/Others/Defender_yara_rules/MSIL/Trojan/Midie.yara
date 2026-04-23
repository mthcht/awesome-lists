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

