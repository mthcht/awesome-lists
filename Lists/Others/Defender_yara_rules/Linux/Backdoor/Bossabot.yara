rule Backdoor_Linux_Bossabot_A_2147817851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Bossabot.A!xp"
        threat_id = "2147817851"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Bossabot"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SCANRND2" ascii //weight: 2
        $x_1_2 = "/tmp/ReV1112" ascii //weight: 1
        $x_1_3 = "NOTICE %s :SD" ascii //weight: 1
        $x_1_4 = "$wop = base64_decode($wop)" ascii //weight: 1
        $x_1_5 = "NOTICE %s :rnd2 %s t %s t %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Bossabot_B_2147822362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Bossabot.B!xp"
        threat_id = "2147822362"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Bossabot"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "scanrnd" ascii //weight: 1
        $x_1_2 = "rm -r /tmp/pool" ascii //weight: 1
        $x_1_3 = "NOTICE %s :Removed all spoofs" ascii //weight: 1
        $x_1_4 = "pkill minerd" ascii //weight: 1
        $x_1_5 = "BoSSaBoTv2-%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

