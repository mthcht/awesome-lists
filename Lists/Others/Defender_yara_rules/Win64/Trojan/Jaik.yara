rule Trojan_Win64_Jaik_VDE_2147975312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Jaik.VDE!MTB"
        threat_id = "2147975312"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {b7 28 24 f5 a4 14 ad 32 1d d8 6b ab 5f 5d 59 26 31 35 79 06 3d de 2a e6 9d 7c fe 90 28 3c 69 0f 5c 96 7c 6e 1d 4c 99 58 53 75 05 6a d0 33 a1 c4 76 db be 92 80 3f 6e 2c 0f d1 dc ad 81 fc b7 3f db 6a}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Jaik_VDG_2147975314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Jaik.VDG!MTB"
        threat_id = "2147975314"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Deleting program files and data" wide //weight: 2
        $x_2_2 = "Startup entry written" wide //weight: 2
        $x_2_3 = "taskkill /f /im" wide //weight: 2
        $x_1_4 = "Installer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Jaik_VDF_2147975380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Jaik.VDF!MTB"
        threat_id = "2147975380"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 ea b8 00 00 00 00 b9 0d 00 00 00 48 89 d7 f3 48 ab c7 45 00 68 00 00 00 c7 45 3c 01 00 00 00 66 c7 45 40 00 00 66 0f ef c0 0f 11 45 e0 66 0f d6 45 f0 48 8d 45 70 48 89 c1}  //weight: 5, accuracy: High
        $x_1_2 = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Add-MpPreference -ExclusionPath" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

