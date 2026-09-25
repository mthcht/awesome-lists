rule Trojan_Linux_CurlBackRAT_AB_2147978559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CurlBackRAT.AB!MTB"
        threat_id = "2147978559"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CurlBackRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c7 40 32 3c 0b 41 88 7c 0c 01 32 04 0b 48 83 c1 01 39 cd 7f ea}  //weight: 2, accuracy: High
        $x_3_2 = {89 d1 32 08 48 83 c0 01 88 48 ff 31 ca 48 39 f0 75 ee}  //weight: 3, accuracy: High
        $x_1_3 = "setexeccon" ascii //weight: 1
        $x_1_4 = "openpty" ascii //weight: 1
        $x_1_5 = "curl_easy_perform" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_CurlBackRAT_AC_2147978560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CurlBackRAT.AC!MTB"
        threat_id = "2147978560"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CurlBackRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {41 32 14 04 48 89 c1 41 88 54 07 03 48 83 c0 01 48 39 f1 75 eb}  //weight: 3, accuracy: High
        $x_3_2 = {32 14 03 48 89 c1 41 88 54 07 03 48 83 c0 01 48 39 ce 75 ec}  //weight: 3, accuracy: High
        $x_3_3 = {41 32 14 06 48 89 c1 88 54 07 03 48 83 c0 01 49 39 c9 75 ec}  //weight: 3, accuracy: High
        $x_1_4 = "socket" ascii //weight: 1
        $x_1_5 = "openpty" ascii //weight: 1
        $x_1_6 = "ttyname" ascii //weight: 1
        $x_1_7 = "ioctl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_CurlBackRAT_LZ_2147978828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CurlBackRAT.LZ!MTB"
        threat_id = "2147978828"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CurlBackRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 5d e4 8b 45 e4 48 98 0f b6 80 1f 34 40 00 83 f0 88 89 c1 48 8b 55 c0 48 63 c3 88 0c 02 83 45 e4 01}  //weight: 3, accuracy: High
        $x_3_2 = {8b 5d e4 8b 45 e4 48 98 0f b6 80 30 3f 40 00 83 f0 28 89 c1 48 8b 55 90 48 63 c3 88 0c 02 83 45 e4 01}  //weight: 3, accuracy: High
        $x_3_3 = {8b 4d e0 8b 45 e0 0f b6 80 a2 c7 04 08 83 f0 28 89 c2 8b 45 d0 88 14 08 83 45 e0 01}  //weight: 3, accuracy: High
        $x_1_4 = "/proc/%d/cmdline" ascii //weight: 1
        $x_1_5 = "/root/.bash_history" ascii //weight: 1
        $x_1_6 = "/tmp/jasper-log" ascii //weight: 1
        $x_1_7 = "/var/log/auth.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

