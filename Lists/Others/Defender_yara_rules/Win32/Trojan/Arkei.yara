rule Trojan_Win32_Arkei_NEA_2147833198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Arkei.NEA!MTB"
        threat_id = "2147833198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Arkei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "gosizepeyabuxijavusadiculihazasa" ascii //weight: 5
        $x_5_2 = "sijewenudapegiginotolut" ascii //weight: 5
        $x_5_3 = "GetMailslotInfo" ascii //weight: 5
        $x_5_4 = "mupexabetor" ascii //weight: 5
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "GetTickCount" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

