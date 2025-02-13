rule Trojan_Win32_MpTamperSrvDisableDiagTrack_A_2147782362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvDisableDiagTrack.A"
        threat_id = "2147782362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvDisableDiagTrack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 00 63 00 20 00 73 00 74 00 6f 00 70 00 20 00 [0-4] 64 00 69 00 61 00 67 00 74 00 72 00 61 00 63 00 6b 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

