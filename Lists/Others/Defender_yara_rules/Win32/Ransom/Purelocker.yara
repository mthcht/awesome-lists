rule Ransom_Win32_Purelocker_A_2147745010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Purelocker.A!MSR"
        threat_id = "2147745010"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Purelocker"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 72 79 70 74 6f 70 70 2e 64 6c 6c 00 44 65 6c 65 74 65 4d 75 73 69 63 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 46 69 6e 64 4d 75 73 69 63 00 4d 6f 76 65 4d 75 73 69 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

