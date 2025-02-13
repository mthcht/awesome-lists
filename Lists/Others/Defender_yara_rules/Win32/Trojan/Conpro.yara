rule Trojan_Win32_Conpro_B_2147622848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conpro.B"
        threat_id = "2147622848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conpro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 c0 9f 83 f8 17 0f 87 ?? ?? 00 00 33 c9 8a 88 ?? ?? ?? ?? ff 24 8d ?? ?? ?? ?? 8b 74 24 ?? 83 c9 ff 8b fe 33 c0 f2 ae}  //weight: 4, accuracy: Low
        $x_1_2 = "as:p:e:m:x:u:" ascii //weight: 1
        $x_1_3 = "CONNECT %s:%d HTTP/1.0" ascii //weight: 1
        $x_1_4 = {41 50 4f 43 41 4c 49 50 54 4f 5f 54 48 45 00}  //weight: 1, accuracy: High
        $x_1_5 = {72 63 66 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "tunnel test ok!!!" ascii //weight: 1
        $x_1_7 = "no create udp socket!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Conpro_C_2147622849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conpro.C"
        threat_id = "2147622849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conpro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 c0 9e 83 f8 16 0f 87 ?? ?? 00 00 33 c9 8a 88 ?? ?? ?? ?? ff 24 8d ?? ?? ?? ?? 8b 54 24 ?? 52 e8}  //weight: 4, accuracy: Low
        $x_1_2 = "b:m:x:u:" ascii //weight: 1
        $x_1_3 = "CONNECT %s:%d HTTP/1.0" ascii //weight: 1
        $x_1_4 = {72 63 78 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = "no configure!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

