rule Trojan_Win32_TelemonRAT_A_2147980541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TelemonRAT.A!AMTB"
        threat_id = "2147980541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TelemonRAT"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.telegram.org/bot" ascii //weight: 1
        $x_1_2 = "MONITOR ACTIVO" ascii //weight: 1
        $x_1_3 = "Tomando screenshot" ascii //weight: 1
        $x_1_4 = "/sendPhoto" ascii //weight: 1
        $x_1_5 = "Streaming activado" ascii //weight: 1
        $x_1_6 = "HWIDs autorizados" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

