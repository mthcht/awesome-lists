rule Trojan_Win32_Unfender_A_2147626262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Unfender.A"
        threat_id = "2147626262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Unfender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oyvmhvtgei\\bmjc\\fee.pdb" ascii //weight: 1
        $x_1_2 = "it's infected by a Virus or cracked. This file won't work anymore." ascii //weight: 1
        $x_1_3 = "Defender Software" wide //weight: 1
        $x_1_4 = "Antivirus Software" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

