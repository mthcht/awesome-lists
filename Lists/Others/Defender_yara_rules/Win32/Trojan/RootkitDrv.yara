rule Trojan_Win32_RootkitDrv_MP_2147835362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RootkitDrv.MP!MTB"
        threat_id = "2147835362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RootkitDrv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 16 03 d1 33 c9 8a 02 84 c0 74 15 0f 1f 40 00 c1 c9 0d 8d 52 01 0f be c0 03 c8 8a 02 84 c0 75 ef 8b 45 fc 3b 4d f0 74 18 8b 4d f8 47 83 c6 04 83 c3 02 3b 78 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RootkitDrv_ARA_2147896747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RootkitDrv.ARA!MTB"
        threat_id = "2147896747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RootkitDrv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\WINDOWS\\SYSTEM32\\DNFly615.exe" ascii //weight: 2
        $x_2_2 = "CTFNOM.exe/CTFN0M.exe/CTFMOM.exe/CTFM0M.exe/CTFM0N.exe/CIFMOM.exe/CIFN0N.exe/DNFly615.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RootkitDrv_AMTB_2147948143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RootkitDrv!AMTB"
        threat_id = "2147948143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RootkitDrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\r77-x64.pdb" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\MasonWizNon" ascii //weight: 1
        $x_1_3 = "-rootkit-master" ascii //weight: 1
        $x_1_4 = "\\n3r-" ascii //weight: 1
        $x_1_5 = "r77-x64.dll" ascii //weight: 1
        $n_100_6 = "Uninst.exe" ascii //weight: -100
        $n_100_7 = "Uninstaller.exe" ascii //weight: -100
        $n_100_8 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

