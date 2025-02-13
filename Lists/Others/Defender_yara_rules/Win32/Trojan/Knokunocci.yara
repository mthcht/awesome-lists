rule Trojan_Win32_Knokunocci_A_2147706731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Knokunocci.A"
        threat_id = "2147706731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Knokunocci"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dGFzay5kbnMtc3luLmNvbQ==" ascii //weight: 2
        $x_1_2 = "sa.htm?id=42498698&refe=&location=test&color=32x&resolution=1024*768&returning=0&language=zh-cn&ua=" ascii //weight: 1
        $x_1_3 = "count4.51yes.com" ascii //weight: 1
        $x_1_4 = "BIN\\TASK\\Task.pdb" ascii //weight: 1
        $x_1_5 = "{\"body\": {\"sample\": 239, \"pubkey\": [3471, 5893]}, \"tag\": \"token\", \"type\": \"socket\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

