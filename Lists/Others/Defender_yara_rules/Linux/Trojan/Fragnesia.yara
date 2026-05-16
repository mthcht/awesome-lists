rule Trojan_Linux_Fragnesia_Z_2147969362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Fragnesia.Z!MTB"
        threat_id = "2147969362"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Fragnesia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/usr/bin/su" ascii //weight: 1
        $x_1_2 = {48 8d 15 24 33 00 00 8b 45 9c 41 b8 10 00 00 00 48 89 d1 ba 01 00 00 00 be 17 01 00 00 89 c7 e8 27 f7 ff ff 85 c0}  //weight: 1, accuracy: High
        $x_1_3 = "unshare(CLONE_NEWUSER)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Fragnesia_DA_2147969453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Fragnesia.DA!MTB"
        threat_id = "2147969453"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Fragnesia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 03 00 3e 00 01 00 00 00 68 00 00 00 00 00 00 00 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 38 00 01 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 2f 62 69 6e 2f 73 68 00 78 00 00 00 00 00 00 00 78 00 00 00 00 00 00 00 b0 69 0f 05 48 8d 3d dd ff ff ff 6a 3b 58 0f 05}  //weight: 10, accuracy: High
        $x_1_2 = "/usr/bin/su" ascii //weight: 1
        $x_1_3 = "unshare(CLONE_NEWUSER)" ascii //weight: 1
        $x_1_4 = "/bin/sh" ascii //weight: 1
        $x_1_5 = "/usr/bin/mount" ascii //weight: 1
        $x_1_6 = "/usr/bin/passwd" ascii //weight: 1
        $x_1_7 = "/usr/bin/chsh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

