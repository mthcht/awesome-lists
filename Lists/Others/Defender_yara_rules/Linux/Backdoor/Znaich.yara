rule Backdoor_Linux_Znaich_A_2147818200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Znaich.A!xp"
        threat_id = "2147818200"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Znaich"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LIBC_FATAL_STDERR_" ascii //weight: 1
        $x_1_2 = "%d*%dMHZ" ascii //weight: 1
        $x_1_3 = "GETCONF_DIR" ascii //weight: 1
        $x_1_4 = "delete[]" ascii //weight: 1
        $x_1_5 = "Multihop attempted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

