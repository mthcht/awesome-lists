rule Trojan_Win32_Ninject_RA_2147828453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninject.RA!MTB"
        threat_id = "2147828453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pentylenetetrazol.dll" ascii //weight: 1
        $x_1_2 = "Afdelingskonference.ini" ascii //weight: 1
        $x_1_3 = "Kursusledelsen.ini" ascii //weight: 1
        $x_1_4 = "Software\\Fadderens" ascii //weight: 1
        $x_1_5 = "Hyalophane.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

