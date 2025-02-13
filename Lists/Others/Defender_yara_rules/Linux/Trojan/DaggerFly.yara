rule Trojan_Linux_DaggerFly_A_2147925339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DaggerFly.A!MTB"
        threat_id = "2147925339"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DaggerFly"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "DARKWOODS9ab992ff1bb02eeb" ascii //weight: 2
        $x_2_2 = "inject_getfunc %s OK" ascii //weight: 2
        $x_2_3 = "elfpaste_bak" ascii //weight: 2
        $x_1_4 = "no selfrecover!" ascii //weight: 1
        $x_1_5 = "tmp/sunspnes" ascii //weight: 1
        $x_2_6 = {48 81 c4 00 04 00 00 5b 41 5c c9 c3 55 48 89 e5 41 54 53 48 81 ec 00 04 00 00 48 89 fb 48 89 b5 f8 fb ff ff 48 89 95 f0 fb ff ff 48 ?? ?? ?? ?? ?? ?? b8 00 00 00 00 ba 7d 00 00 00 48 89 f7 48 89 d1 f3 48 ab 48 83 bd f0 fb ff ff 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

