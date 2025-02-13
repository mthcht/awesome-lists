rule Trojan_Linux_Pumakit_A_2147932202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Pumakit.A!MTB"
        threat_id = "2147932202"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Pumakit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PUMA %s" ascii //weight: 2
        $x_2_2 = "Kitsune PID %ld" ascii //weight: 2
        $x_2_3 = ".puma-config" ascii //weight: 2
        $x_2_4 = "zarya" ascii //weight: 2
        $x_2_5 = "kit_so_len" ascii //weight: 2
        $x_1_6 = "/usr/share/zov_f" ascii //weight: 1
        $x_1_7 = "ping_interval_s" ascii //weight: 1
        $x_1_8 = "session_timeout_s" ascii //weight: 1
        $x_1_9 = "c2_timeout_s" ascii //weight: 1
        $x_1_10 = "LD_PRELOAD=/lib64/libs.so" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

