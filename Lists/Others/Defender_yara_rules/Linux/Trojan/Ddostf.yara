rule Trojan_Linux_Ddostf_A_2147784141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Ddostf.A!MTB"
        threat_id = "2147784141"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Ddostf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "var/run/klss.pid" ascii //weight: 1
        $x_1_2 = "ddos.tf" ascii //weight: 1
        $x_1_3 = "/var/tmp/test.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Ddostf_Dx_2147797805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Ddostf.Dx!xp"
        threat_id = "2147797805"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Ddostf"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 57 56 53 81 ec c8 00 00 00 8d 5d c4 c7 45 cc 00 00 00 00 c7 45 d0 00 00 00 00 a1 a4 a1 0c 08 66 c1 c8 08 66 89 45 c6 66 c7 45 c4 02 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 c8 83 c4 0c 6a 00 6a 01 6a 02 e8 ?? ?? ?? ?? 89 c6}  //weight: 5, accuracy: Low
        $x_1_2 = "UDP-Flow" ascii //weight: 1
        $x_1_3 = "SYN-Flow" ascii //weight: 1
        $x_1_4 = "bXlzcy5iYXNlYy5jYw==" ascii //weight: 1
        $x_1_5 = "var/run/klss.pid" ascii //weight: 1
        $x_1_6 = "/var/tmp/test.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

