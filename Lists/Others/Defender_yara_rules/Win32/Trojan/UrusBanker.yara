rule Trojan_Win32_UrusBanker_RPY_2147852649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrusBanker.RPY!MTB"
        threat_id = "2147852649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrusBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "download.cpudln.com" wide //weight: 1
        $x_1_2 = "117.79.80.169" wide //weight: 1
        $x_1_3 = "P2P.vbp" wide //weight: 1
        $x_1_4 = "windows\\lock.log" wide //weight: 1
        $x_1_5 = "epldrive.dll" ascii //weight: 1
        $x_1_6 = "urlmon" ascii //weight: 1
        $x_1_7 = "DownUrl" ascii //weight: 1
        $x_1_8 = "modSocketMaster" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

