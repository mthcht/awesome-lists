rule Trojan_Win32_Pscradle_RPS_2147837481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pscradle.RPS!MTB"
        threat_id = "2147837481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pscradle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ndtpro.xyz/nj" wide //weight: 10
        $x_10_2 = "osecweb.ir/js" wide //weight: 10
        $x_1_3 = "powershell -command IEX(New-Object Net.Webclient).DownloadString(" wide //weight: 1
        $x_1_4 = "config_40.ps1" wide //weight: 1
        $x_1_5 = "ping 127.0.0.1 && del" wide //weight: 1
        $x_1_6 = "loader.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

