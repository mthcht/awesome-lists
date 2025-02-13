rule PWS_Win32_Oirtuk_A_2147692837_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Oirtuk.A"
        threat_id = "2147692837"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Oirtuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cio - no orkut -" ascii //weight: 1
        $x_1_2 = "Oi amor.." ascii //weight: 1
        $x_1_3 = "orkut - Efetuar login - Microsoft Internet Explorer" ascii //weight: 1
        $x_3_4 = "ORKUT Auto Infect" ascii //weight: 3
        $x_1_5 = "Senha..........." ascii //weight: 1
        $x_1_6 = "orkut.com/Compose.aspx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

