rule Trojan_Win32_Medphar_A_2147694553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Medphar.A"
        threat_id = "2147694553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Medphar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hq-pharma.org/_id_" ascii //weight: 1
        $x_1_2 = "drivers\\system.exe %" ascii //weight: 1
        $x_1_3 = {99 33 c2 2b c2 83 c0 17 8d ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

