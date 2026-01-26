rule Trojan_Win32_SusRundll_ABC_2147961723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRundll.ABC!MTB"
        threat_id = "2147961723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRundll"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUNDLL32.EXE" wide //weight: 1
        $x_1_2 = "\\AppData\\Local\\ServeMaps\\DxsableOoad\\MBAMRwsdehebl.dll" wide //weight: 1
        $x_1_3 = "SofiuMMzcqlHiganq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

