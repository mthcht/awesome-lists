rule Tampering_Win32_SuspWerFaultSec_A_2147953840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Tampering:Win32/SuspWerFaultSec.A"
        threat_id = "2147953840"
        type = "Tampering"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWerFaultSec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " /pid " wide //weight: 1
        $x_1_2 = "WerFaultSecure.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

