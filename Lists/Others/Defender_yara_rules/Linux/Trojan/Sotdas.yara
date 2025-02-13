rule Trojan_Linux_Sotdas_A_2147784136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Sotdas.A!MTB"
        threat_id = "2147784136"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Sotdas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/etc/init.d/iptables stop > /dev/null" ascii //weight: 1
        $x_1_2 = "reSuSEfirewall2 stop > /dev/null" ascii //weight: 1
        $x_1_3 = "ufw disable > /dev/null" ascii //weight: 1
        $x_1_4 = {6e 65 74 73 74 61 74 20 2d 61 6e 70 20 7c 20 67 72 65 70 [0-5] 3a [0-6] 7c 61 77 6b 20 27 7b 70 72 69 6e 74 20 24 4e 46 7d 27 20 7c 63 75 74 20 2d 64 [0-21] 78 61 72 67 73 20 6b 69 6c 6c 20 2d 39 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 3b 66 72 65 65 20 2d 6d 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c}  //weight: 1, accuracy: Low
        $x_1_5 = "chmod 777 /tmp/gconfd.bin" ascii //weight: 1
        $x_1_6 = "ln -s /etc/init.d/%s /etc/rc2.d/S77%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

