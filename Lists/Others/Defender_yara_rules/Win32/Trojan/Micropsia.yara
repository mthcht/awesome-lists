rule Trojan_Win32_Micropsia_A_2147730661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Micropsia.A"
        threat_id = "2147730661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Micropsia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "my-files.host/api/hazard" wide //weight: 1
        $x_1_2 = "SELECT * FROM AntiVirusProduct" wide //weight: 1
        $x_1_3 = "winmgmts:\\\\localhost\\root\\SecurityCenter2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

