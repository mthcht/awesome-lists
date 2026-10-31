rule Trojan_Win64_GCleaner_LVK_2147969877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GCleaner.LVK!MTB"
        threat_id = "2147969877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d c8 03 fa 03 fb 03 f8 6a 00 ?? ?? ?? ?? ?? 31 3e 83 c3 04 83 c6 04 3b 5d cc 72 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GCleaner_SA_2147976564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GCleaner.SA!MTB"
        threat_id = "2147976564"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "XpSimulateParanoid" ascii //weight: 3
        $x_3_2 = "Average ymcjteezpitktwqnwtxv Record coquwmiwfyfauikjeczmv Record artfsohjmxqyehsciqoqu Average xtrzpaikurvocdgvbxia" ascii //weight: 3
        $x_3_3 = "LlLtLuMnosmidnil125625NaN m=finptrobj()" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GCleaner_VG_2147977702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GCleaner.VG!MTB"
        threat_id = "2147977702"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 c2 73 11 8d 0c 16 44 8a 44 14 70 48 ff c2 44 30 04 0f eb eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GCleaner_GV_2147981300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GCleaner.GV!MTB"
        threat_id = "2147981300"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 f2 1b 8a c3 32 c2 32 c1 32 45 ff 8a 8e ?? ?? ?? ?? 32 45 fe 88 45 f8 8a c1 02 c0 84 c9 79 02}  //weight: 1, accuracy: Low
        $x_1_2 = "/F /Create /TN Microsoft_Silverlight /sc minute /MO 1 /TR" ascii //weight: 1
        $x_1_3 = "/C reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Alight /t REG_SZ /d" ascii //weight: 1
        $x_1_4 = "Rundll32.exe SHELL32.DLL,ShellExec_RunDLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

