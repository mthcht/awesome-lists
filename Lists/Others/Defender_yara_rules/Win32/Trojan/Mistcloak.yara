rule Trojan_Win32_Mistcloak_SK_2147837777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mistcloak.SK!MTB"
        threat_id = "2147837777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mistcloak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\usb.ini" ascii //weight: 1
        $x_1_2 = "autorun.inf\\Protection for Autorun\\System Volume Information\\usb.ini" ascii //weight: 1
        $x_1_3 = "G:\\project\\APT\\U" ascii //weight: 1
        $x_1_4 = "\\new\\u2ec\\Release\\u2ec.pdb" ascii //weight: 1
        $x_1_5 = "ServerGetUsbDevName" ascii //weight: 1
        $x_1_6 = "ServerGetUsbDevStatus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

