rule Trojan_Win32_Wepiall_A_2147689025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wepiall.A"
        threat_id = "2147689025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wepiall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 67 63 51 7d 71 71 66 69 ?? ?? ?? 23 4a 6b 6f 69 22 45 6e 69 28 56 64 70 75 6b 66 66 2a}  //weight: 10, accuracy: Low
        $x_10_2 = {4a 6b 69 6f 44 64 6e ?? ?? ?? 21 75 61 61 21 52 6c 73 74 6d 60 64}  //weight: 10, accuracy: Low
        $x_1_3 = "q`mtglyl{,c06:0*jzf" ascii //weight: 1
        $x_1_4 = "m#Cmn&Qfqthba&" ascii //weight: 1
        $x_1_5 = "win%ca%cb%cd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

