rule Trojan_Win32_MalSckTaskDll_B_2147953431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalSckTaskDll.B!MTB"
        threat_id = "2147953431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalSckTaskDll"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $x_1_3 = "rundll32.exe" wide //weight: 1
        $x_1_4 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 72 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 [0-80] 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_5 = "dllregisterserver" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

