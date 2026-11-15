rule Trojan_Win32_RemoteMSI_DA_2147982156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteMSI.DA!MTB"
        threat_id = "2147982156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteMSI"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msiexec.exe" wide //weight: 1
        $x_10_2 = "http://185.241.211.197" wide //weight: 10
        $x_1_3 = ".msi?" wide //weight: 1
        $x_1_4 = "/qn /norestart" wide //weight: 1
        $x_1_5 = "=Exploited" wide //weight: 1
        $n_20_6 = "OpenAI" wide //weight: -20
        $n_20_7 = "deepseek" wide //weight: -20
        $n_20_8 = "claude" wide //weight: -20
        $n_20_9 = "codex" wide //weight: -20
        $n_20_10 = "copilot" wide //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

