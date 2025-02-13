rule Trojan_Win32_MalGen_C_2147909960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalGen.C"
        threat_id = "2147909960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalGen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A at L %d" ascii //weight: 1
        $x_1_2 = "tcpip_thread" ascii //weight: 1
        $x_1_3 = "208.67.222.222" ascii //weight: 1
        $x_1_4 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

