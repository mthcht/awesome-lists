rule Trojan_Win32_SusPSExec_ABD_2147961724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPSExec.ABD!MTB"
        threat_id = "2147961724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPSExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "irm" wide //weight: 1
        $x_1_3 = "emeditorjp.com" wide //weight: 1
        $x_1_4 = "| iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

