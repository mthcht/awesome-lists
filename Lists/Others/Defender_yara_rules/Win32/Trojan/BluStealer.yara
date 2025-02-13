rule Trojan_Win32_BluStealer_ER_2147828068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BluStealer.ER!MTB"
        threat_id = "2147828068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BluStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoWallets.zip" wide //weight: 1
        $x_1_2 = "api.telegram.org/bot" wide //weight: 1
        $x_1_3 = "FilesGrabber" wide //weight: 1
        $x_1_4 = "tr e nu niSODom .ed" ascii //weight: 1
        $x_1_5 = "CurrentVersion\\RunOnce\\*RD_" wide //weight: 1
        $x_1_6 = "Templates\\Stub\\Project1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

