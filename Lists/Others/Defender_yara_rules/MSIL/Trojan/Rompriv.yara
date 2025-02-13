rule Trojan_MSIL_Rompriv_A_2147683472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rompriv.A"
        threat_id = "2147683472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rompriv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keepMinerAlive" ascii //weight: 1
        $x_1_2 = "url {0} --threads {1} --userpass {2}" wide //weight: 1
        $x_1_3 = "runMiner" ascii //weight: 1
        $x_1_4 = "aprovos.miner:yparxw22" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

