rule Trojan_Win32_VShell_2147976549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VShell!atmn"
        threat_id = "2147976549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VShell"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$7201f9f9-52a8-4b8c-bdf2-f2a7518ea1f3" ascii //weight: 1
        $x_1_2 = "D:\\Desktop\\linshi\\x\\new-ChomeSetup\\AdminCheckCode\\obj\\Debug\\UpdaterSetup.pdb" ascii //weight: 1
        $x_1_3 = "GoogleAuthValidator" ascii //weight: 1
        $x_1_4 = "ReleaseFileToTemp" ascii //weight: 1
        $x_1_5 = "ProcessMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

