rule Trojan_Win32_CastleRat_ACL_2147956966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CastleRat.ACL!MTB"
        threat_id = "2147956966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CastleRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.ip-api.com" wide //weight: 1
        $x_2_2 = "-no-deelevate" wide //weight: 2
        $x_3_3 = "--mute-audio --do-not-de-elevate" wide //weight: 3
        $x_4_4 = "UAC_InputIndicatorOverlayWnd" wide //weight: 4
        $x_1_5 = "camera!" wide //weight: 1
        $x_1_6 = "keylog.txt" wide //weight: 1
        $x_1_7 = "powershell Start-Sleep -Seconds 3; Remove-Item -Path %ws -Force" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

