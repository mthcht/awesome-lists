rule Trojan_Win32_Megcor_SA_2147744197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Megcor.SA!MTB"
        threat_id = "2147744197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Megcor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!-!_README_!-!.rtf" ascii //weight: 1
        $x_1_2 = "[+] started:" ascii //weight: 1
        $x_1_3 = ".cmd %1% cipher wmic" ascii //weight: 1
        $x_1_4 = "[+] isSanboxed" ascii //weight: 1
        $x_1_5 = "[+] processing" ascii //weight: 1
        $x_1_6 = "del /Q /F" ascii //weight: 1
        $x_1_7 = "echo echo ************************************************************************** >>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

