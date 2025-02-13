rule Trojan_Win32_Dinwood_SP_2147753627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dinwood.SP!MSR"
        threat_id = "2147753627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dinwood"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hfuie32.2ihsfa.com/api/fbtime" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "\\FBCookiesWin32\\Release" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dinwood_RPX_2147896323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dinwood.RPX!MTB"
        threat_id = "2147896323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dinwood"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 80 37 18 83 c7 04 6a 05 59 ad 31 07 83 c7 04 e2 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

