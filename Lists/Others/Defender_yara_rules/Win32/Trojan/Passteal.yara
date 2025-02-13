rule Trojan_Win32_Passteal_OTY_2147797880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Passteal.OTY!MTB"
        threat_id = "2147797880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Passteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f1 10 c6 85 5e ff ff ff 01 c1 f9 03 89 8d ac fd ff ff c6 45 a8 01 89 4d ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Passteal_MA_2147815734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Passteal.MA!MTB"
        threat_id = "2147815734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Passteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "37238328-1324242-5456786-8fdff0-67547552436675" wide //weight: 30
        $x_2_2 = "UnmapViewOfFile" ascii //weight: 2
        $x_2_3 = "Decrypt" ascii //weight: 2
        $x_2_4 = "ForceRemove" wide //weight: 2
        $x_2_5 = "permission denied" ascii //weight: 2
        $x_2_6 = "LockFileEx" ascii //weight: 2
        $x_2_7 = "IsProcessorFeaturePresent" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

