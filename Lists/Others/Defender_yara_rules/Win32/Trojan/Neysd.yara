rule Trojan_Win32_Neysd_A_2147686561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neysd.A"
        threat_id = "2147686561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neysd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?aaaa=3333&ffff=%s" ascii //weight: 1
        $x_1_2 = "%s:RUN_REBOOT" ascii //weight: 1
        $x_1_3 = "Password Expiried Time:" ascii //weight: 1
        $x_1_4 = "cert2013.dat" ascii //weight: 1
        $x_1_5 = "SD_2013 Is Running!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

