rule Trojan_Win32_Tesyong_A_2147685623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tesyong.A"
        threat_id = "2147685623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tesyong"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c netsh advfirewall firewall add rule name=\"System Thread\" protocol=TCP dir=in action=allow" wide //weight: 1
        $x_1_2 = "cmd /c netsh firewall set opmode disable" wide //weight: 1
        $x_1_3 = "#Information#" wide //weight: 1
        $x_1_4 = "popall.com" wide //weight: 1
        $x_1_5 = "HongSy" wide //weight: 1
        $x_1_6 = "KillSelf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

