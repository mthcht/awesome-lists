rule Trojan_Linux_Miners_A_2147773956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Miners.A"
        threat_id = "2147773956"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Miners"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "500"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/.x1munix" wide //weight: 10
        $x_10_2 = "/wipefse" wide //weight: 10
        $x_10_3 = "/cpuminer-multi" wide //weight: 10
        $x_10_4 = "/getmonero" wide //weight: 10
        $x_10_5 = "/xmr.service" wide //weight: 10
        $x_10_6 = "/xm64" wide //weight: 10
        $x_10_7 = "/xm32" wide //weight: 10
        $x_10_8 = "/dockerminer" wide //weight: 10
        $x_10_9 = "/xmrdemo" wide //weight: 10
        $x_10_10 = "/oceanhole" wide //weight: 10
        $x_10_11 = "/watchbog" wide //weight: 10
        $x_10_12 = "/cryptonight" wide //weight: 10
        $x_10_13 = "/nicehashminer" wide //weight: 10
        $x_10_14 = "/ethminer" wide //weight: 10
        $x_10_15 = "/equihash" wide //weight: 10
        $x_10_16 = "/NsCpuCNMiner64" wide //weight: 10
        $x_10_17 = "/minergate" wide //weight: 10
        $x_10_18 = "/minerd" wide //weight: 10
        $x_10_19 = "/xmr-stak-cpu" wide //weight: 10
        $x_10_20 = "/xmrig" wide //weight: 10
        $x_10_21 = "/xmr-stak" wide //weight: 10
        $x_10_22 = "/stratum" wide //weight: 10
        $x_10_23 = "/AnXqV.yam" wide //weight: 10
        $x_10_24 = "/xmrigDaemon" wide //weight: 10
        $x_10_25 = "/xmrigMiner" wide //weight: 10
        $x_10_26 = "/apaceha" wide //weight: 10
        $x_10_27 = "/mixnerdx" wide //weight: 10
        $x_10_28 = "/XbashY" wide //weight: 10
        $x_10_29 = "/crypto-pool" wide //weight: 10
        $x_10_30 = "/minexmr" wide //weight: 10
        $x_10_31 = "/XJnRj" wide //weight: 10
        $x_10_32 = "/NXLAi" wide //weight: 10
        $x_10_33 = "/BI5zj" wide //weight: 10
        $x_10_34 = "/askdljlqw" wide //weight: 10
        $x_10_35 = "/ysaydh" wide //weight: 10
        $x_10_36 = "/bonns" wide //weight: 10
        $x_10_37 = "/donns" wide //weight: 10
        $x_10_38 = "/kxjd" wide //weight: 10
        $x_10_39 = "/Duck.sh" wide //weight: 10
        $x_10_40 = "/bonn.sh" wide //weight: 10
        $x_10_41 = "/kworker34" wide //weight: 10
        $x_10_42 = "/irqbalanc1" wide //weight: 10
        $x_10_43 = "/ddg.2011" wide //weight: 10
        $x_10_44 = "/wnTKYg" wide //weight: 10
        $x_10_45 = "/JnKihGjn" wide //weight: 10
        $x_10_46 = "/irqba2anc1" wide //weight: 10
        $x_10_47 = "/irqba5xnc1" wide //weight: 10
        $x_10_48 = "/irqbnc1" wide //weight: 10
        $x_10_49 = "/ir29xc1" wide //weight: 10
        $x_10_50 = "/xig" wide //weight: 10
        $x_10_51 = "/cranberry" wide //weight: 10
        $x_10_52 = "/.gpg-agent" wide //weight: 10
        $n_100_53 = "/stratum/" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (50 of ($x*))
}

