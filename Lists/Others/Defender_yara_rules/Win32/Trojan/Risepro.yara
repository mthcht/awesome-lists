rule Trojan_Win32_Risepro_RPX_2147852904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Risepro.RPX!MTB"
        threat_id = "2147852904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Risepro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 fa 3b 66 ff c2 80 ea 1d f6 d0 c1 f2 99 66 c1 f2 af f6 d1 22 c1 c1 c2 30 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Risepro_RPZ_2147897309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Risepro.RPZ!MTB"
        threat_id = "2147897309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Risepro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 80 b6 ?? ?? ?? ?? b4 6a 00 ff d7 80 86 ?? ?? ?? ?? f6 6a 00 ff d7 80 86 ?? ?? ?? ?? f9 6a 00 ff d7 80 b6 ?? ?? ?? ?? fd 6a 00 ff d7 80 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

