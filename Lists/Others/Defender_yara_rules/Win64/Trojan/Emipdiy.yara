rule Trojan_Win64_Emipdiy_B_2147815180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emipdiy.B"
        threat_id = "2147815180"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emipdiy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "3C29FEA2-6FE8-4BF9-B98A-0E3442115F67" wide //weight: 5
        $x_5_2 = {4c 64 72 41 64 64 [0-10] 50 72 6f 63 65 73 73 4c 6f 61 64}  //weight: 5, accuracy: Low
        $x_2_3 = ":\\hooker" wide //weight: 2
        $x_2_4 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e [0-32] 6d 79 5f 61 70 70 6c 69 63 61 74 69 6f 6e 5f 70 61 74 68}  //weight: 2, accuracy: Low
        $x_1_5 = "\\Windows Mail\\wab.exe" ascii //weight: 1
        $x_1_6 = "\\Windows Mail\\wabmig.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Emipdiy_CM_2147816177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emipdiy.CM!MTB"
        threat_id = "2147816177"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emipdiy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "lodqcbw041xd9.dll" ascii //weight: 3
        $x_3_2 = "IternalJob" ascii //weight: 3
        $x_3_3 = "SetPath" ascii //weight: 3
        $x_3_4 = "GetVolumeNameForVolumeMountPointW" ascii //weight: 3
        $x_3_5 = "SetProcessShutdownParameters" ascii //weight: 3
        $x_3_6 = "RegisterShellHookWindow" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Emipdiy_CN_2147896089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Emipdiy.CN!MTB"
        threat_id = "2147896089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Emipdiy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LdrAddx64.dll" ascii //weight: 3
        $x_3_2 = "Z:\\hooker2" wide //weight: 3
        $x_3_3 = "rundll32.exe my_application_path, ProcessLoad" ascii //weight: 3
        $x_3_4 = "\\Windows Mail\\wab.exe" ascii //weight: 3
        $x_3_5 = "CoSetProxyBlanket" ascii //weight: 3
        $x_3_6 = "SELECT * FROM Win32_ComputerSystemProduct" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

