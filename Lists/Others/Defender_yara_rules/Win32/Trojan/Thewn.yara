rule Trojan_Win32_Thewn_A_2147597109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Thewn.A"
        threat_id = "2147597109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Thewn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%20=)&Nome=OIEU&De=ip@zip.com&Para=jach1090@gmail.com" ascii //weight: 1
        $x_1_2 = "\\svhostss.exe" ascii //weight: 1
        $x_1_3 = "http://www.piram.com.br/hosts.txt" ascii //weight: 1
        $x_1_4 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

