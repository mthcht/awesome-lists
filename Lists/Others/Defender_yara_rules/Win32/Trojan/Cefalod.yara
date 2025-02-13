rule Trojan_Win32_Cefalod_A_2147710204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cefalod.A!bit"
        threat_id = "2147710204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cefalod"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2e 76 6d 70 32 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = "adoplay.xcm.icafe8.net" ascii //weight: 10
        $x_10_3 = "QQ_TSEH_FLAG_%d" wide //weight: 10
        $x_1_4 = {00 71 71 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 52 52 00 5c 5c 2e 5c 70 69 70 65 5c 53 57 4e 54 72 61 63 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

