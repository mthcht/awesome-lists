rule Trojan_Win32_Kuta_A_2147658726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kuta.A"
        threat_id = "2147658726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 45 97 01 31 33 c0 5a 59 59}  //weight: 1, accuracy: High
        $x_1_2 = "noga-ruka" ascii //weight: 1
        $x_1_3 = "stat/tuk/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

