rule Trojan_Win32_SusPsExec_IK_2147968626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPsExec.IK!MTB"
        threat_id = "2147968626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPsExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Downloads\\CPU.exe" wide //weight: 1
        $x_1_2 = ".png' -Value" wide //weight: 1
        $x_1_3 = "rEgX.cmd" wide //weight: 1
        $x_1_4 = ".StartsWith('::'" wide //weight: 1
        $x_1_5 = "Substring(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

