rule Backdoor_Linux_Dofloo_A_2147757419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Dofloo.A!MTB"
        threat_id = "2147757419"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Dofloo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DNS_Flood" ascii //weight: 1
        $x_1_2 = "UDP_Flood" ascii //weight: 1
        $x_1_3 = "DealwithDDoS(_MSGHEAD" ascii //weight: 1
        $x_1_4 = "sed -i -e '/exit/d' /etc/rc.local" ascii //weight: 1
        $x_1_5 = "sed -i -e '2 i/etc/%s reboot' /etc/rc.local" ascii //weight: 1
        $x_1_6 = "ddos.tf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Dofloo_A_2147794898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Dofloo.A!xp"
        threat_id = "2147794898"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Dofloo"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hacker" ascii //weight: 1
        $x_1_2 = "VERSONEX:Linux-%s|%d|%d MHz|%dMB|%dMB|%s" ascii //weight: 1
        $x_1_3 = "sed -i -e '/%s/d' /etc/rc.local" ascii //weight: 1
        $x_1_4 = "sed -i -e '2 i%s/%s' /etc/rc.local" ascii //weight: 1
        $x_1_5 = "sed -i -e '2 i%s/%s start' /etc/rc.d/rc.local" ascii //weight: 1
        $x_1_6 = "sed -i -e '2 i%s/%s start' /etc/init.d/boot.local" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

