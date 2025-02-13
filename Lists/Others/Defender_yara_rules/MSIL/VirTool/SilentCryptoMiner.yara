rule VirTool_MSIL_SilentCryptoMiner_2147892905_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/SilentCryptoMiner"
        threat_id = "2147892905"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SilentCryptoMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Release\\Silent Crypto Miner Builder.pdb" ascii //weight: 2
        $x_1_2 = "SilentCryptoMiner.AlgorithmSelection.resources" ascii //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionPath @($env:UserProfile" wide //weight: 1
        $x_1_4 = "Select a cryptocurrency (algorithm) to mine" wide //weight: 1
        $x_1_5 = "DefRootkit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

