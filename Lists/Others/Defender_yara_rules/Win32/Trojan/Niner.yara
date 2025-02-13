rule Trojan_Win32_Niner_A_2147628894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Niner.A"
        threat_id = "2147628894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Niner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{68EF98DE-9D4F-489A-A11F-963C0A170386} = s 'Auto'" ascii //weight: 1
        $x_1_2 = "C:\\WINDOWS\\9u.ini" ascii //weight: 1
        $x_1_3 = "url.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

