rule Trojan_Linux_SutersuRootKit_B_2147795717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SutersuRootKit.B!MTB"
        threat_id = "2147795717"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SutersuRootKit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".cmd.Upload_Passwd.PasswordInfo" ascii //weight: 1
        $x_1_2 = {33 72 64 70 61 72 74 79 2f 70 72 6f 74 6f 62 75 66 2d [0-16] 2f 73 72 63 2f 67 6f 6f 67 6c 65 2f 70 72 6f 74 6f 62 75 66 2f [0-37] 2e 68}  //weight: 1, accuracy: Low
        $x_1_3 = {33 72 64 70 61 72 74 79 2f 62 6f 6f 73 74 5f [0-16] 2f 62 6f 6f 73 74 2f 61 73 69 6f 2f 64 65 74 61 69 6c 2f [0-20] 2e 68 70 70}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 72 6f 6f 74 2f 44 65 76 65 6c 2f 33 72 64 50 61 72 74 79 2f 6c 69 62 73 73 68 2d [0-16] 2f 73 72 63 2f [0-21] 2e 63}  //weight: 1, accuracy: Low
        $x_1_5 = {2f 72 6f 6f 74 2f 44 65 76 65 6c 2f 50 72 6f 6a 65 63 74 73 2f 72 6f 6f 74 6b 69 74 2f 33 72 64 70 61 72 74 79 2f 70 6f 63 6f 2d [0-16] 2d 61 6c 6c 2f 46 6f 75 6e 64 61 74 69 6f 6e 2f 69 6e 63 6c 75 64 65 2f 50 6f 63 6f 2f [0-24] 2e 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SutersuRootKit_A_2147795718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SutersuRootKit.A!MTB"
        threat_id = "2147795718"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SutersuRootKit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/root/engine/my-engine/sample/rootkit/suterusu-master" ascii //weight: 1
        $x_1_2 = {6e 5f 74 63 70 ?? 5f 73 65 71 5f 73 68 6f 77}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 5f 75 64 70 ?? 5f 73 65 71 5f 73 68 6f 77}  //weight: 1, accuracy: Low
        $x_1_4 = "n_proc_filldir" ascii //weight: 1
        $x_1_5 = "n_dev_get_flags" ascii //weight: 1
        $x_1_6 = "get_tcp_seq_show" ascii //weight: 1
        $x_1_7 = "/suterusu.mod.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

