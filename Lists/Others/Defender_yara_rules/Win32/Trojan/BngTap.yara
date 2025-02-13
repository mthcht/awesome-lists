rule Trojan_Win32_BngTap_A_2147752154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BngTap.A!MTB"
        threat_id = "2147752154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BngTap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" ascii //weight: 1
        $x_1_2 = "Select * From AntiVirusProduct" ascii //weight: 1
        $x_1_3 = "/api/primewire/%s/requests" ascii //weight: 1
        $x_1_4 = "Taskkill /IM  %s /F &  %s" ascii //weight: 1
        $x_1_5 = "daenerys=%s&betriebssystem=%s&anwendung=%s&AV=%s&frankie=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

