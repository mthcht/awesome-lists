rule Trojan_Win32_Polerter_A_2147682475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Polerter.A"
        threat_id = "2147682475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Polerter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Alerter3ClientCS.Resources" wide //weight: 1
        $x_1_2 = "'pwned!" wide //weight: 1
        $x_1_3 = "&fakecrash" wide //weight: 1
        $x_1_4 = "/updater/acrord32.exe" wide //weight: 1
        $x_1_5 = "/keys/keys.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

