rule Trojan_Win32_Tapxamy_A_2147730799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tapxamy.A"
        threat_id = "2147730799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapxamy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PYG.dll" ascii //weight: 10
        $x_10_2 = "nthook.dll" wide //weight: 10
        $x_10_3 = "Software\\BaymaxPatchTools\\InjectDll" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

