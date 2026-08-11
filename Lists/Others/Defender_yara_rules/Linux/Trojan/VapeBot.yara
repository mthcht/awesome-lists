rule Trojan_Linux_VapeBot_GVA_2147975949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/VapeBot.GVA!MTB"
        threat_id = "2147975949"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "VapeBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 8d 44 24 ?? 48 ba 72 65 73 6f 6c 76 65 2d 48 b9 73 79 73 74 65 6d 64 2d 48 89 e6 89 ef 66 c7 04 24 01 00 48 89 50 ?? c7 40 ?? 63 68 65 63 ba 18 00 00 00 66 c7 40 ?? 6b 00 c6 44 24 ?? 00 48 89 4c 24 ?? e8 ?? ?? ?? ?? ff c0}  //weight: 15, accuracy: Low
        $x_4_2 = "VapeBot has been executed" ascii //weight: 4
        $x_4_3 = "vapebot" ascii //weight: 4
        $x_4_4 = "/bin/sys_monitor_cnr" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

