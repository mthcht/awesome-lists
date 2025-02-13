rule Backdoor_Linux_SpyEye_A_2147823859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/SpyEye.A!xp"
        threat_id = "2147823859"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "SpyEye"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo \"/corefile/core-%e-%p-%t\" > /proc/sys/kernel/core_pattern" ascii //weight: 1
        $x_1_2 = "/lib/5d570686-37ee-11e2-b228-000c292cb65c" ascii //weight: 1
        $x_1_3 = "/tmp/itklog.txt" ascii //weight: 1
        $x_1_4 = "mkdir /corefile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

