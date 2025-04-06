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

rule Trojan_Linux_Pumakit_B_2147938039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Pumakit.B!MTB"
        threat_id = "2147938039"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Pumakit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 38 02 75 26 31 ff e8 f2 47 02 00 48 89 df be 41 00 00 00 ba ed 01 00 00 31 c0 e8 a8 e1 01 00 85 c0 78 07 89 c7}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 d9 41 89 c0 31 c0 e8 06 52 02 00 48 89 df e8 8b e1 01 00 bf 54 00 00 00 4c 89 f6 31 c0 e8 08 ff 01 00 85 c0 0f 85 fb 22 00 00 48 8d 3d ee 14 03 00 31 f6 31 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

