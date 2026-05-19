rule Trojan_Linux_DirtyMerge_DA_2147969663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DirtyMerge.DA!MTB"
        threat_id = "2147969663"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DirtyMerge"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3e 00 01 00 00 00 78 00 40 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 38 00 01 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 40 00 00 00 00 00 b8 00 00 00 00 00 00 00 b8 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 31 ff 31 f6 31 c0 b0 6a 0f 05 b0 69 0f 05 b0 74 0f 05 6a 00 48 8d 05 12 00 00 00 50 48 89 e2 48 8d 3d 12 00 00 00 31 f6 6a 3b 58 0f 05 54 45 52 4d 3d 78 74 65 72 6d 00 2f 62 69 6e 2f 73 68 00 00 00 00 00 00 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "/usr/bin/su" ascii //weight: 1
        $x_1_3 = "unshare(CLONE_NEWUSER)" ascii //weight: 1
        $x_1_4 = "/bin/sh" ascii //weight: 1
        $x_1_5 = "/usr/bin/mount" ascii //weight: 1
        $x_1_6 = "/usr/bin/passwd" ascii //weight: 1
        $x_1_7 = "/usr/bin/chsh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

