rule Trojan_Win32_Smkload_SK_2147834141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smkload.SK!MTB"
        threat_id = "2147834141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smkload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "harabarapuxedicuyacuranecaviner" ascii //weight: 1
        $x_1_2 = "yimifitihijucagiwesiwanicitolijeroxapawobuyetubiwoleza" ascii //weight: 1
        $x_1_3 = "fudezecimigazone" ascii //weight: 1
        $x_1_4 = "rucihozicefiw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

