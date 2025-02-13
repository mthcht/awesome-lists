rule Misleading_MacOS_CoinMiner_BA_288863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:MacOS/CoinMiner.BA!MTB"
        threat_id = "288863"
        type = "Misleading"
        platform = "MacOS: "
        family = "CoinMiner"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "XMR-Stak-Miner" ascii //weight: 2
        $x_1_2 = "CPU backend miner config file" ascii //weight: 1
        $x_1_3 = "pool.usxmrpool.com:3333" ascii //weight: 1
        $x_1_4 = "CPU mining code by tevador and SChernykh" ascii //weight: 1
        $x_1_5 = "RandomX_MoneroConfig" ascii //weight: 1
        $x_1_6 = "donate.xmr-stak.net:14441" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Misleading_MacOS_CoinMiner_BC_291959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:MacOS/CoinMiner.BC!MTB"
        threat_id = "291959"
        type = "Misleading"
        platform = "MacOS: "
        family = "CoinMiner"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mining.set_target" ascii //weight: 1
        $x_1_2 = "stratum+ssl://randomx.xmrig.com:443" ascii //weight: 1
        $x_1_3 = "donate.v2.xmrig.com:3333" ascii //weight: 1
        $x_1_4 = ".config/xmrig.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

