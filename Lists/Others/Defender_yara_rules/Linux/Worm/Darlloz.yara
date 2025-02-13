rule Worm_Linux_Darlloz_A_2147684398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Linux/Darlloz.A"
        threat_id = "2147684398"
        type = "Worm"
        platform = "Linux: Linux platform"
        family = "Darlloz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/var/run/.zollard/" ascii //weight: 1
        $x_1_2 = "insmod /lib/modules/`uname -r`/kernel/net/ipv4/netfilter/iptable" ascii //weight: 1
        $x_1_3 = "iptables -D INPUT -p tcp --dport 23 -j DROP" ascii //weight: 1
        $x_1_4 = {77 67 65 74 20 2d 4f 20 2f 74 6d 70 2f 78 38 36 20 [0-64] 2f 78 38 36}  //weight: 1, accuracy: Low
        $x_1_5 = "70%72%65%70%65%6E%64%5F%66%69%6C%65%3D%70%68%70%3A%2" ascii //weight: 1
        $x_1_6 = "elseif (is_callable(\"passthru\") and !in_array(\"passthru\",$disablefunc)) {$v = @ob_get_contents(); @ob_clean(); passthru($cmd);" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

