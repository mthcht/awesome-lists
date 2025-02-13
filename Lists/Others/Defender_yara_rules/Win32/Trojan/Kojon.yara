rule Trojan_Win32_Kojon_A_2147682271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kojon.A"
        threat_id = "2147682271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kojon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExploit_Exeinfect" ascii //weight: 1
        $x_1_2 = "Anti Virus Option.lnk" wide //weight: 1
        $x_1_3 = "\\attack_temp\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

