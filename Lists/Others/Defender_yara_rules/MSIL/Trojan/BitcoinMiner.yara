rule Trojan_MSIL_BitcoinMiner_A_2147706775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitcoinMiner.A"
        threat_id = "2147706775"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitcoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InjectPE" wide //weight: 1
        $x_1_2 = "infinitybot" wide //weight: 1
        $x_1_3 = "cgminer" wide //weight: 1
        $x_1_4 = "coin-miner" wide //weight: 1
        $x_1_5 = "BitcoinMiner" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

