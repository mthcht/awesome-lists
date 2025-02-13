rule Trojan_Win32_RagnarLocker_A_2147753437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RagnarLocker.A!MSR"
        threat_id = "2147753437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RagnarLocker"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RAGNAR SECRET" ascii //weight: 1
        $x_1_2 = ".ragnar_" wide //weight: 1
        $x_1_3 = "bootsect.bak" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

