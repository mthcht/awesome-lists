rule Trojan_Linux_Samblad_A_2147756834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Samblad.A!MTB"
        threat_id = "2147756834"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Samblad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "samba-root-shellcode.c" ascii //weight: 2
        $x_2_2 = "samba-root-findsock.c" ascii //weight: 2
        $x_2_3 = "samba-root-system.c" ascii //weight: 2
        $x_1_4 = "change_to_root_user" ascii //weight: 1
        $x_1_5 = "samba_init_module" ascii //weight: 1
        $x_1_6 = "PAYLOAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

