rule Trojan_Win32_Powcod_RPJ_2147840061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powcod.RPJ!MTB"
        threat_id = "2147840061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powcod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "Hidden powershell" wide //weight: 1
        $x_1_3 = "Invoke-webrequest" wide //weight: 1
        $x_1_4 = "grantable-excesses.000webhostapp.com/index" wide //weight: 1
        $x_1_5 = ".txt" wide //weight: 1
        $x_1_6 = "UseBasicParsing" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

