rule Trojan_Win32_TopAntiSpyware_2147569826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TopAntiSpyware"
        threat_id = "2147569826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TopAntiSpyware"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WINDOWS\\Web\\desktop.html" ascii //weight: 1
        $x_1_2 = "com.ms.applet.enable." ascii //weight: 1
        $x_1_3 = {00 63 3a 5c 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 49 4e 44 4f 57 53 5c 53 79 73 74 65 6d 33 32 5c [0-5] 73 72 76 33 32 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

