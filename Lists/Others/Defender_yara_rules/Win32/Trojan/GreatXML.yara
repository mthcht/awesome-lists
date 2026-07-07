rule Trojan_Win32_GreatXML_DA_2147973065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GreatXML.DA!MTB"
        threat_id = "2147973065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GreatXML"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "&gt;&gt;" wide //weight: 1
        $x_1_3 = "\\pe.cmd" wide //weight: 1
        $x_1_4 = "echo:start" wide //weight: 1
        $x_1_5 = "\\Windows\\System32\\conhost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

