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

