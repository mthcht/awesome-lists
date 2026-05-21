rule Trojan_Linux_DirtyDecrypt_DA_2147969854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DirtyDecrypt.DA!MTB"
        threat_id = "2147969854"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DirtyDecrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b0 69 0f 05 48 8d 3d dd ff ff ff 6a 3b 58 0f 05}  //weight: 10, accuracy: High
        $x_1_2 = "/usr/bin/su" ascii //weight: 1
        $x_1_3 = "unshare(CLONE_NEWUSER)" ascii //weight: 1
        $x_1_4 = "/bin/sh" ascii //weight: 1
        $x_1_5 = "/usr/bin/mount" ascii //weight: 1
        $x_1_6 = "/usr/bin/passwd" ascii //weight: 1
        $x_1_7 = "/usr/bin/chsh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

