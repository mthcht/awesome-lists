rule HackTool_Linux_PNScan_A_2147767152_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PNScan.A!MTB"
        threat_id = "2147767152"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PNScan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ipv4bot.whatismyipaddress.com:" ascii //weight: 1
        $x_1_2 = "pnscan] starting pnscan" ascii //weight: 1
        $x_1_3 = "setminercmd" ascii //weight: 1
        $x_1_4 = {3a 2f 2f 77 77 77 2e 6c 79 73 61 74 6f 72 2e 6c 69 75 2e 73 65 2f 7e 70 65 6e 2f 70 6e 73 63 61 6e [0-21] 43 6f 6d 6d 61 6e 64 20 6c 69 6e 65 20 6f 70 74 69 6f 6e 73 3a}  //weight: 1, accuracy: Low
        $x_1_5 = "pool.supportxmr.com' >> /etc/hosts;echo '0.0.0.0 pinto.mamointernet.icu' >> /etc/hosts;" ascii //weight: 1
        $x_1_6 = "anti] [suspicion] [kill] is telnet" ascii //weight: 1
        $x_1_7 = "mv %s/xmrig %s" ascii //weight: 1
        $x_1_8 = "car /proc/self/exe | %s printf 512 /tmp/slime >> /etc/init.d/rcS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

