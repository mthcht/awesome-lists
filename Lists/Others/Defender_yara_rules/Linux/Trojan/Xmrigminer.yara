rule Trojan_Linux_Xmrigminer_B_2147772368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Xmrigminer.B"
        threat_id = "2147772368"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Xmrigminer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "pool.minexmr.com" wide //weight: 5
        $x_1_2 = "-u " wide //weight: 1
        $x_1_3 = "-B" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Xmrigminer_C_2147772461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Xmrigminer.C"
        threat_id = "2147772461"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Xmrigminer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "pool.supportxmr.com" wide //weight: 10
        $x_10_2 = "pool.support" wide //weight: 10
        $x_10_3 = "pool.monero.hashvault.pro" wide //weight: 10
        $x_10_4 = "xmrpool.eu" wide //weight: 10
        $x_10_5 = "cryptonight-hub.miningpoolhub.com" wide //weight: 10
        $x_10_6 = "xmrpool.net" wide //weight: 10
        $x_10_7 = "xmr.nanopool.org" wide //weight: 10
        $x_10_8 = "mixpools.org" wide //weight: 10
        $x_10_9 = "minergate.com" wide //weight: 10
        $x_10_10 = "viaxmr.com" wide //weight: 10
        $x_10_11 = "moriaxmr.com" wide //weight: 10
        $x_10_12 = "xmr.suprnova.cc" wide //weight: 10
        $x_10_13 = "moneroocean.stream" wide //weight: 10
        $x_10_14 = "xmrpool.de" wide //weight: 10
        $x_10_15 = "poolto.be" wide //weight: 10
        $x_10_16 = "mineXMR.com" wide //weight: 10
        $x_10_17 = "xmr.prohash.net" wide //weight: 10
        $x_10_18 = "sheepman.mine.bz" wide //weight: 10
        $x_10_19 = "xmr.mypool.online" wide //weight: 10
        $x_10_20 = "bohemianpool.com" wide //weight: 10
        $x_10_21 = "moneropool.com" wide //weight: 10
        $x_10_22 = "moneropool.nl" wide //weight: 10
        $x_10_23 = "iwanttoearn.money" wide //weight: 10
        $x_10_24 = "pool.xmr.pt" wide //weight: 10
        $x_10_25 = "monero.crypto-pool.fr" wide //weight: 10
        $x_10_26 = "monero.miners.pro" wide //weight: 10
        $x_10_27 = "minercircle.com" wide //weight: 10
        $x_10_28 = "monero.lindon-pool.win" wide //weight: 10
        $x_10_29 = "cryptmonero.com" wide //weight: 10
        $x_10_30 = "teracycle.net" wide //weight: 10
        $x_10_31 = "ratchetmining.com" wide //weight: 10
        $x_10_32 = "dwarfpool.com" wide //weight: 10
        $x_10_33 = "monerohash.com" wide //weight: 10
        $x_10_34 = "monero.us.to" wide //weight: 10
        $x_10_35 = "usxmrpool.com" wide //weight: 10
        $x_10_36 = "xmrpool.xyz" wide //weight: 10
        $x_10_37 = "minemonero.gq" wide //weight: 10
        $x_10_38 = "alimabi.cn" wide //weight: 10
        $x_10_39 = "pooldd.com" wide //weight: 10
        $x_10_40 = "monero.riefly.id" wide //weight: 10
        $x_10_41 = "pool.minergate.com" wide //weight: 10
        $x_10_42 = "xmr.hashinvest" wide //weight: 10
        $x_10_43 = "monero.farm" wide //weight: 10
        $x_10_44 = "monerominers.net" wide //weight: 10
        $x_10_45 = "crypto-pool.fr" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

