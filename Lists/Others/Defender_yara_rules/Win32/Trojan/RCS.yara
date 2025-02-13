rule Trojan_Win32_RCS_A_2147696715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RCS.A"
        threat_id = "2147696715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RCS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "98C5250D-C29A-4985-AE5F-AFE5367E5006" wide //weight: 1
        $x_1_2 = "services\\bthclient" wide //weight: 1
        $x_1_3 = "SmsFilter.dll" wide //weight: 1
        $x_1_4 = "Contacts: All" wide //weight: 1
        $x_1_5 = "Contact from:" wide //weight: 1
        $x_1_6 = "Start=%02i.%02i.%04i.00.00" wide //weight: 1
        $x_1_7 = "Windows.Phone.Media.Capture.PhotoCaptureDevice" wide //weight: 1
        $x_1_8 = "/licenses/by-nc-nd/" wide //weight: 1
        $x_2_9 = "11B69356-6C6D-475D-8655-D29B240D96C8" wide //weight: 2
        $x_2_10 = "nc-7-8dv.cfg" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

