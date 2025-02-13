rule Trojan_Win32_Dogcall_2147729582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogcall"
        threat_id = "2147729582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogcall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Final1stspy\\hadowexecute - Copy\\Release\\hadowexecute.pdb" ascii //weight: 1
        $x_1_2 = "%s?MachineId=%s&InfoSo=%s&Index=%s&Account=%s&Group=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

