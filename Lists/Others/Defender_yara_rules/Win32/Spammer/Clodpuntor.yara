rule Spammer_Win32_Clodpuntor_A_2147601811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Clodpuntor.A"
        threat_id = "2147601811"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Clodpuntor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "RND_HEX" ascii //weight: 3
        $x_3_2 = "RANDSUBJ" ascii //weight: 3
        $x_3_3 = "667 WSAStartup error" ascii //weight: 3
        $x_3_4 = "netsh firewall set allowedprogram \"%s\" enable" ascii //weight: 3
        $x_1_5 = "REAL_IP" ascii //weight: 1
        $x_1_6 = "DATEB" ascii //weight: 1
        $x_1_7 = "FROM_MX" ascii //weight: 1
        $x_1_8 = "667 gethostbyname error" ascii //weight: 1
        $x_1_9 = "667%%20gethostbyname%%20error" ascii //weight: 1
        $x_1_10 = "----=_NextPart_%%03d_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

