rule Trojan_Win32_SoguSec_A_2147957202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SoguSec.A!dha"
        threat_id = "2147957202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SoguSec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 31 32 33 34 35 36 37 38 39 41 42 43 ?? 45 46 88 13 00 00 60 ea 00 00}  //weight: 1, accuracy: Low
        $n_1_2 = "@CXUsb@" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

