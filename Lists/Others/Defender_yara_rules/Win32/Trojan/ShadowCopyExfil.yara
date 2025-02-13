rule Trojan_Win32_ShadowCopyExfil_A_2147840730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowCopyExfil.A"
        threat_id = "2147840730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowCopyExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "diskshadow" wide //weight: 1
        $x_1_2 = "ntdsutil" wide //weight: 1
        $x_1_3 = "dsdbutil" wide //weight: 1
        $n_5_4 = {20 00 2d 00 3f 00 00 00}  //weight: -5, accuracy: High
        $n_5_5 = {20 00 2f 00 3f 00 00 00}  //weight: -5, accuracy: High
        $n_5_6 = "\\onetouch\\" wide //weight: -5
        $n_5_7 = "\\commvault\\" wide //weight: -5
        $n_5_8 = "hds\\backup" wide //weight: -5
        $n_5_9 = "\\Rackware-winutil" wide //weight: -5
        $n_5_10 = "work\\pol-" wide //weight: -5
        $n_5_11 = "set dsrm" wide //weight: -5
        $n_5_12 = "connect to" wide //weight: -5
        $n_5_13 = {73 00 6e 00 61 00 70 00 73 00 68 00 6f 00 74 00 [0-240] 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 31 00}  //weight: -5, accuracy: Low
        $n_5_14 = "set dsrm pass" wide //weight: -5
        $n_5_15 = "\\avepoint" wide //weight: -5
        $n_5_16 = "networker" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

