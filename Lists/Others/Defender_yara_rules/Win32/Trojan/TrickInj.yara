rule Trojan_Win32_TrickInj_A_2147752998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickInj.A!MTB"
        threat_id = "2147752998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[INIT] Alive = %u" ascii //weight: 1
        $x_1_2 = "[INIT] Inj = %u" ascii //weight: 1
        $x_1_3 = "[INIT] BC = %u" ascii //weight: 1
        $x_1_4 = "#pgid#" ascii //weight: 1
        $x_1_5 = "inj_32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrickInj_B_2147766713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickInj.B!MTB"
        threat_id = "2147766713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[INIT] BC = %u" ascii //weight: 1
        $x_1_2 = "#pgid#" ascii //weight: 1
        $x_1_3 = "inj_32.dll" ascii //weight: 1
        $x_1_4 = "#gid#" ascii //weight: 1
        $x_1_5 = {23 69 64 23 [0-47] 51 43 6f 6e 6e 65 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_1_7 = {84 c0 75 ec 81 f6 34 70 00 10 81 fe 5f b8 ec 0e 74 25 81 fe 7b f8 87 0f 74 19 81 fe a5 50 5a c3 74 0d 33 c0 81 fe 8f 22 34 ea 0f 94 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

