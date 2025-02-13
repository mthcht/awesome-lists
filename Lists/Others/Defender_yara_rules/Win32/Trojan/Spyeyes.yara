rule Trojan_Win32_Spyeyes_RPJ_2147838346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spyeyes.RPJ!MTB"
        threat_id = "2147838346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyeyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6{~}2.204.41.192/AMSI/ecco.exe" wide //weight: 1
        $x_1_2 = "Pr{~}ogramData\\ecco.exe" wide //weight: 1
        $x_1_3 = "62.204.41.192/-RED/RED.oo" wide //weight: 1
        $x_1_4 = "replace('{Jok}" wide //weight: 1
        $x_1_5 = "C:\\ProgramData\\LOD.exe" wide //weight: 1
        $x_1_6 = "6{~}2.204.41.192/-LOD/LOD.exe" wide //weight: 1
        $x_1_7 = "Pr{~}ogramData\\LOD.exe" wide //weight: 1
        $x_1_8 = "p{~}{~}o{~}we{~}{~}rs{~}{~}h{~}el{~}{~}l{~}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

