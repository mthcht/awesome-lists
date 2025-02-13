rule TrojanDownloader_Linux_Samdown_2147724981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Samdown"
        threat_id = "2147724981"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Samdown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "spawn_reverse_shell" ascii //weight: 4
        $x_2_2 = "samba_init_module" ascii //weight: 2
        $x_2_3 = "change_to_root_user" ascii //weight: 2
        $x_2_4 = "Hello from the Samba" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

