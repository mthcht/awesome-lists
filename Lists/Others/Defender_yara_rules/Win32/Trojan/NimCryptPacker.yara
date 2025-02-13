rule Trojan_Win32_NimCryptPacker_A_2147848959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NimCryptPacker.A"
        threat_id = "2147848959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NimCryptPacker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@[*] Found Syscall Stub: " ascii //weight: 1
        $x_1_2 = "fatal.nim" ascii //weight: 1
        $x_1_3 = "hashcommon.nim" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

