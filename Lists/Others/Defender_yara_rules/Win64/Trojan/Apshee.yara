rule Trojan_Win64_Apshee_GVA_2147962784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Apshee.GVA!MTB"
        threat_id = "2147962784"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Apshee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.ibsensoftware.com/" ascii //weight: 1
        $x_1_2 = "GetWindowThreadProcessId" ascii //weight: 1
        $x_1_3 = "RegisterServiceCtrlHandlerW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

