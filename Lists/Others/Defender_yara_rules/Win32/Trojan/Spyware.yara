rule Trojan_Win32_Spyware_ARR_2147964017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spyware.ARR!MTB"
        threat_id = "2147964017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_9_1 = "wmi := ComObjGet(\"winmgmts:\")" ascii //weight: 9
        $x_11_2 = "query := wmi.ExecQuery(\"Select * from Win32_Process\")" ascii //weight: 11
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

