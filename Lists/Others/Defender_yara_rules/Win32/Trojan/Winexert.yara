rule Trojan_Win32_Winexert_C_2147716906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winexert.C!bit"
        threat_id = "2147716906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winexert"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "winlsecsrv.sys" wide //weight: 10
        $x_10_2 = "BFB11D6E-1C7E-4784-9FC0-1A233899F4AB" wide //weight: 10
        $x_10_3 = {5c 53 6d 61 72 74 45 6e 67 69 6e 65 5c 42 69 6e 5c 57 69 6e 33 32 5c [0-32] 5c 45 58 [0-16] 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_1_4 = "Mutex_BIDUI18NGUID_" wide //weight: 1
        $x_1_5 = "%%SystemRoot%%\\System32\\svchost.exe -k %s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

