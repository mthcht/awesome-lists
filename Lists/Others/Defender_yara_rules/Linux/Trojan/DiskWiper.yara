rule Trojan_Linux_DiskWiper_A_2147794563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DiskWiper.A"
        threat_id = "2147794563"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DiskWiper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "dd " wide //weight: 5
        $x_55_2 = "of=/dev/sda" wide //weight: 55
        $n_5_3 = "mkinitramfs" wide //weight: -5
        $n_5_4 = "u-boot.imx" wide //weight: -5
        $n_5_5 = ".iso" wide //weight: -5
        $n_5_6 = ".img" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Linux_DiskWiper_B_2147799373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DiskWiper.B"
        threat_id = "2147799373"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DiskWiper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "shred " wide //weight: 50
        $x_50_2 = "wipe " wide //weight: 50
        $x_50_3 = "sfill " wide //weight: 50
        $x_50_4 = "smem " wide //weight: 50
        $x_50_5 = "scrub " wide //weight: 50
        $x_50_6 = "dc3dd " wide //weight: 50
        $x_50_7 = "dcfldd " wide //weight: 50
        $n_10_8 = "stat " wide //weight: -10
        $n_10_9 = "ls " wide //weight: -10
        $n_10_10 = "logger " wide //weight: -10
        $n_10_11 = "blkid " wide //weight: -10
        $x_1_12 = "/dev/sd" wide //weight: 1
        $x_1_13 = "/dev/sg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

