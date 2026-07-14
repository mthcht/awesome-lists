rule Trojan_Linux_jscramSteal_DA_2147973337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/jscramSteal.DA!MTB"
        threat_id = "2147973337"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "jscramSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bpf_object__open_mem" ascii //weight: 1
        $x_1_2 = "bpf_program__attach" ascii //weight: 1
        $x_1_3 = "libbpf.so.1" ascii //weight: 1
        $x_1_4 = "bpf_object__load" ascii //weight: 1
        $x_1_5 = "bpf_map__name" ascii //weight: 1
        $x_1_6 = "MLKEM512" ascii //weight: 1
        $x_1_7 = "HpkeAead" ascii //weight: 1
        $x_1_8 = "@ec2-imds" ascii //weight: 1
        $x_1_9 = "IllegalMiddleboxChangeCipherSpec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

