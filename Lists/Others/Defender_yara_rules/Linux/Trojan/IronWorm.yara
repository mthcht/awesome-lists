rule Trojan_Linux_IronWorm_DA_2147971072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/IronWorm.DA!MTB"
        threat_id = "2147971072"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "IronWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/proc/" ascii //weight: 1
        $x_1_2 = "self/ex" ascii //weight: 1
        $x_1_3 = "/dev/shm" ascii //weight: 1
        $x_1_4 = "memfd_create()" ascii //weight: 1
        $x_1_5 = "O_TMPFILE" ascii //weight: 1
        $x_1_6 = "PTRACEfT" ascii //weight: 1
        $x_1_7 = "linkpat" ascii //weight: 1
        $x_1_8 = "ARJ archiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

