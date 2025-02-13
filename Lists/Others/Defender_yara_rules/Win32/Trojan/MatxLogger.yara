rule Trojan_Win32_MatxLogger_B_2147765637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MatxLogger.B!MTB"
        threat_id = "2147765637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MatxLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Recovered Screenshot Logger" ascii //weight: 1
        $x_1_2 = "Recovered keystrokes" ascii //weight: 1
        $x_1_3 = "Recovered Voice Logger" ascii //weight: 1
        $x_1_4 = "Recovered Clipboard Logger" ascii //weight: 1
        $x_1_5 = "Recovered Passwords" ascii //weight: 1
        $x_1_6 = "Matiex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_MatxLogger_B_2147765676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MatxLogger.B!!MatxLogger.gen!MTB"
        threat_id = "2147765676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MatxLogger"
        severity = "Critical"
        info = "MatxLogger: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Recovered Screenshot Logger" ascii //weight: 1
        $x_1_2 = "Recovered keystrokes" ascii //weight: 1
        $x_1_3 = "Recovered Voice Logger" ascii //weight: 1
        $x_1_4 = "Recovered Clipboard Logger" ascii //weight: 1
        $x_1_5 = "Recovered Passwords" ascii //weight: 1
        $x_1_6 = "Matiex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

