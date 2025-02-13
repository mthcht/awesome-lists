rule Trojan_AndroidOS_Exodus_A_2147783373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Exodus.A"
        threat_id = "2147783373"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Exodus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "onPrivateServiceStartCommand" ascii //weight: 2
        $x_1_2 = "setStagingHost" ascii //weight: 1
        $x_1_3 = "ad1.fbsba.com" ascii //weight: 1
        $x_1_4 = "Lg4PVX1eQV9rdSkOCBx5XERYa399CQkcfQhIDHF3f10JCXpZ" ascii //weight: 1
        $x_1_5 = "eddd0317-2bdc-4140-86cb-0e8d7047b874" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

