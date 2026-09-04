rule Trojan_Win32_Blackbasta_LR_2147977530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackbasta.LR!MTB"
        threat_id = "2147977530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackbasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%kings advised( recollect Barbed/ via@" ascii //weight: 1
        $x_2_2 = "driver+ %d Faint! Cigarette \"hopefully? chemist Collar! Beaming" ascii //weight: 2
        $x_3_3 = "List %s Strongly) human Bye" ascii //weight: 3
        $x_4_4 = "lent copper %d0Length %s( several_ poor Casks inquired Sparrow-" ascii //weight: 4
        $x_5_5 = "*digging rome ability 192$ 161- Influenced" ascii //weight: 5
        $x_6_6 = "%d/ lessen? shelf" ascii //weight: 6
        $x_7_7 = "disable$ 467/ gnaw Snack Enslave." ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

