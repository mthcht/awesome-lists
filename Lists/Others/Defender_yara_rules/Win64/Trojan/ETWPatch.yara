rule Trojan_Win64_ETWPatch_RPA_2147941070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ETWPatch.RPA!MTB"
        threat_id = "2147941070"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ETWPatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_100_2 = "add-mppreference -exclusionpath 'c:\\','c:\\programdata','c:\\users','c:\\program files (x86)' -force" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

