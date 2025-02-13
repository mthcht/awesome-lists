rule Trojan_Win64_Kluch_A_2147682450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kluch.A"
        threat_id = "2147682450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kluch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ed c8 d7 d8 c5 de ff ed df de d6 de dd df d8 e6 ed df de d8 c2 c3 d4 e7 c5 df d4 c3 c3 c4 f2 ed e5 ff 91 c2 c6 de d5 df d8 e6 ed c5 d7 de c2 de c3 d2 d8 fc ed f4 e3 f0 e6 e5 f7 fe e2 ed d4 df d8 d9 d2 d0 fc ed c8 c3 c5 c2 d8 d6 d4 e3 ed 8c e8 f4 fa e3}  //weight: 1, accuracy: High
        $x_1_2 = {fa fe 91 81 81 83 91 80 9f 80 9e e1 e5 e5 f9 00 85 81 85 91 80 9f 80 9e e1 e5 e5 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Kluch_B_2147684024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kluch.B"
        threat_id = "2147684024"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kluch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WLEventStartShell" ascii //weight: 1
        $x_1_2 = "ZmcGdiConvertMetaFilePict" ascii //weight: 1
        $x_1_3 = {7e 43 48 74 74 70 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = "bProxyEnable=%d,m_PROXY_HOST=%s,m_PROXY_USER=%s" ascii //weight: 1
        $x_1_5 = "5fuza45&LV=20077&V=" ascii //weight: 1
        $x_1_6 = "A95s8U_0O9I7y" ascii //weight: 1
        $x_1_7 = "CreateHTTPConnect hWininet=%p,Addr=%p,hOpenHandle=%p" ascii //weight: 1
        $x_2_8 = {41 c6 43 e1 e9 41 c6 43 e2 7c 41 c6 43 e3 bf 41 c6 43 e4 4f 41 c6 43 e5 7a 41 c6 43 e6 6e 41 c6 43 e7 8f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

