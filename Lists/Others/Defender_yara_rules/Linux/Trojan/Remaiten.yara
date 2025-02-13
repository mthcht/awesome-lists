rule Trojan_Linux_Remaiten_DS_2147796740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Remaiten.DS!MTB"
        threat_id = "2147796740"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Remaiten"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 66 74 70 20 2d 67 20 2d 72 20 61 2e 73 68 20 [0-21] 3b 74 66 74 70 20 2d 67 20 2d 72 20 61 2e 73 68 20 [0-21] 3b 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 [0-24] 2f 61 2e 73 68 3b 77 67 65 74 20 68 74 74 70 [0-24] 2f 61 2e 73 68 3b 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 73 68 20 61 2e 73 68 3b 73 68 20 61 2e 73 68 [0-7] 2e 74}  //weight: 1, accuracy: Low
        $x_1_2 = "/bin/busybox chmod +x retr;./retr>ktn1;/bin/busybox chmod +x ktn1;./ktn1" ascii //weight: 1
        $x_1_3 = "Bot infected via TFTP/wget" ascii //weight: 1
        $x_1_4 = "TSUN4M1 from original KTN" ascii //weight: 1
        $x_1_5 = "KILLBOTS" ascii //weight: 1
        $x_1_6 = "Killing child PID" ascii //weight: 1
        $x_1_7 = "[QB0t] UDP flooder ya dumbass" ascii //weight: 1
        $x_1_8 = "TCP Flooding" ascii //weight: 1
        $x_1_9 = "NSSYNFLOOD" ascii //weight: 1
        $x_1_10 = "QJUNK flooding" ascii //weight: 1
        $x_1_11 = "HTTP Flood" ascii //weight: 1
        $x_1_12 = "Bot unsilenced" ascii //weight: 1
        $x_1_13 = "SYN flooder from the original KTN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

