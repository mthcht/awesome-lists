rule Trojan_Win32_BitRAT_NB_2147895178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BitRAT.NB!MTB"
        threat_id = "2147895178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BitRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bits.ps1" ascii //weight: 1
        $x_1_2 = "cmd.exe /c exec.bat" ascii //weight: 1
        $x_1_3 = "rundll32.exe %s,InstallHinfSection" ascii //weight: 1
        $x_1_4 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32" ascii //weight: 1
        $x_1_5 = "PMSCF" ascii //weight: 1
        $x_1_6 = "DecryptFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

