rule Trojan_Linux_DirtyFrag_DA_2147968826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DirtyFrag.DA!MTB"
        threat_id = "2147968826"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DirtyFrag"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 ff 31 f6 31 c0 b0 6a}  //weight: 10, accuracy: High
        $x_1_2 = "/usr/bin/su" ascii //weight: 1
        $x_1_3 = "TERM=xterm" ascii //weight: 1
        $x_1_4 = "/bin/sh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_DirtyFrag_Z_2147968827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DirtyFrag.Z!MTB"
        threat_id = "2147968827"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DirtyFrag"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 ff 31 f6 31 c0 b0 6a 0f 05 b0 69 0f 05 b0 74 0f 05 6a 00 48 8d 05 12 00 00 00 50 48 89 e2 48 8d 3d 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_DirtyFrag_ZA_2147968828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DirtyFrag.ZA!MTB"
        threat_id = "2147968828"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DirtyFrag"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DIRTYFRAG_VERBOSE" ascii //weight: 1
        $x_1_2 = "DIRTYFRAG_CORRUPT_ONLY" ascii //weight: 1
        $x_1_3 = "dirtyfrag: failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_DirtyFrag_ZC_2147968829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DirtyFrag.ZC!MTB"
        threat_id = "2147968829"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DirtyFrag"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 ff 31 f6 31 c0 b0 6a}  //weight: 1, accuracy: High
        $x_1_2 = "--force-rxrpc" ascii //weight: 1
        $x_1_3 = {ba 00 00 00 00 be 02 00 00 00 bf 02 00 00 00 e8 ca eb ff ff 89 45 f4 83 7d f4 00 0f 88 c4 00 00 00 48 8d 45 c0 ba 28 00 00 00 be 00 00 00 00 48 89 c7 e8 87 e8 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

