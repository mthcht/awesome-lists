rule Trojan_Win32_FluffyWolf_MZZ_2147972745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FluffyWolf.MZZ!MTB"
        threat_id = "2147972745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FluffyWolf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hidden -Command" wide //weight: 1
        $x_1_2 = "irm" wide //weight: 1
        $x_1_3 = "while(1)" wide //weight: 1
        $x_1_4 = "script?id=" wide //weight: 1
        $x_1_5 = "http://" wide //weight: 1
        $x_1_6 = "|iex" wide //weight: 1
        $x_1_7 = "Start-Sleep -Seconds " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

