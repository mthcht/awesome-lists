rule Trojan_Win32_Angod_2147616237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Angod"
        threat_id = "2147616237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Angod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "adonga.cn/count/data" ascii //weight: 2
        $x_2_2 = {66 69 6c 65 6e 61 6d 65 3d [0-6] 6f 70 65 6e}  //weight: 2, accuracy: Low
        $x_1_3 = "getservbyname" ascii //weight: 1
        $x_1_4 = "gethostname" ascii //weight: 1
        $x_1_5 = "getprotobyname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

