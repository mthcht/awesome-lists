rule Trojan_Win32_Cimiwa_A_2147712432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cimiwa.A"
        threat_id = "2147712432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cimiwa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pingd?" ascii //weight: 1
        $x_1_2 = "&keyfrom=" ascii //weight: 1
        $x_1_3 = "%sietar.inf" ascii //weight: 1
        $x_1_4 = "shit.exe" ascii //weight: 1
        $x_1_5 = "GET /w.gif?message" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

