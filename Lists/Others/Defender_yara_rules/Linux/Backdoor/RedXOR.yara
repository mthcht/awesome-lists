rule Backdoor_Linux_RedXOR_A_2147777549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/RedXOR.A!MTB"
        threat_id = "2147777549"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "RedXOR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 48 98 48 03 45 d8 8b 55 f4 48 63 d2 48 03 55 d8 0f b6 0a 0f b6 55 f2 31 ca 88 10 0f b6 45 f3 00 45 f2 83 45 f4 01 8b 45 f4 3b 45 d4 7c cf}  //weight: 1, accuracy: High
        $x_1_2 = ".po1kitd-update-k" ascii //weight: 1
        $x_1_3 = ".po1kitd.thumb" ascii //weight: 1
        $x_1_4 = "/var/tmp/.po1kitd" ascii //weight: 1
        $x_1_5 = {70 79 74 68 6f 6e 20 2d 63 20 [0-16] 70 74 79 3b 70 74 79 2e 73 70 61 77 6e 28 27 2f 62 69 6e 2f 62 61 73 68}  //weight: 1, accuracy: Low
        $x_1_6 = "/usr/syno/etc/rc.d/S99%s.sh" ascii //weight: 1
        $x_1_7 = "POST /yester/login.jsp" ascii //weight: 1
        $x_1_8 = "get_sys_info" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

