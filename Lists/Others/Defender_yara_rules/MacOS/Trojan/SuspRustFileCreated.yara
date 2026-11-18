rule Trojan_MacOS_SuspRustFileCreated_A_2147982181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspRustFileCreated.A"
        threat_id = "2147982181"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspRustFileCreated"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "rust_eh_personality" ascii //weight: 2
        $x_1_2 = "_execvp" ascii //weight: 1
        $x_1_3 = "_posix_spawnp" ascii //weight: 1
        $x_1_4 = "_sqlite3_step" ascii //weight: 1
        $x_1_5 = "_sqlite3_prepare_v2" ascii //weight: 1
        $x_1_6 = "_sqlite3_open_v2" ascii //weight: 1
        $x_1_7 = "_dlsym" ascii //weight: 1
        $x_1_8 = "_dlopen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

