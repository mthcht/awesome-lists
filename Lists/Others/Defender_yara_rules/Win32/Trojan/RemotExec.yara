rule Trojan_Win32_RemotExec_PAA_2147965294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemotExec.PAA!MTB"
        threat_id = "2147965294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemotExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/v /c" wide //weight: 1
        $x_3_2 = {3d 00 25 00 63 00 64 00 25 00 5c 00 [0-63] 2e 00 6c 00 6e 00 6b 00}  //weight: 3, accuracy: Low
        $x_3_3 = "\\AppData\\Local" wide //weight: 3
        $x_3_4 = "&>nul ce!f!tutil -decode" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

